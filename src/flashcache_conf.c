/****************************************************************************
 *  flashcache_conf.c
 *  FlashCache: Device mapper target for block-level disk caching
 *
 *  Copyright 2010 Facebook, Inc.
 *  Author: Mohan Srinivasan (mohan@facebook.com)
 *
 *  Based on DM-Cache:
 *   Copyright (C) International Business Machines Corp., 2006
 *   Author: Ming Zhao (mingzhao@ufl.edu)
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 ****************************************************************************/

#include <asm/atomic.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/pagemap.h>
#include <linux/random.h>
#include <linux/hardirq.h>
#include <linux/sysctl.h>
#include <linux/version.h>
#include <linux/reboot.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
#include "dm.h"
#include "dm-io.h"
#include "dm-bio-list.h"
#include "kcopyd.h"
#else
#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,27)
#include "dm.h"
#endif
#include <linux/device-mapper.h>
#include <linux/bio.h>
#include <linux/dm-kcopyd.h>
#endif

#include "flashcache.h"

int sysctl_flashcache_reclaim_policy = FLASHCACHE_FIFO;
int sysctl_flashcache_write_merge = 1;
/* XXX - Some access to this are MP unsafe, but harmless. Not worth fixing */
int sysctl_flashcache_error_inject = 0;

static struct ctl_table_header *flashcache_table_header;

int sysctl_flashcache_sync;
int sysctl_flashcache_stop_sync = 0;
int sysctl_flashcache_zerostats;
int sysctl_flashcache_dirty_thresh = DIRTY_THRESH_DEF;
int sysctl_flashcache_debug = 0;
int sysctl_max_clean_ios_total = 4;
int sysctl_max_clean_ios_set = 2;
int sysctl_flashcache_max_nc_pids = 100;
int sysctl_nc_pid_expiry_check = 60;
int sysctl_nc_pid_do_expiry = 0;
int sysctl_flashcache_fast_remove = 0;

struct cache_c *cache_list_head = NULL;
struct work_struct _kcached_wq;
u_int64_t size_hist[33];

struct kmem_cache *_job_cache;
mempool_t *_job_pool;
struct kmem_cache *_pending_job_cache;
mempool_t *_pending_job_pool;

atomic_t nr_cache_jobs;
atomic_t nr_pending_jobs;

extern struct list_head *_pending_jobs;
extern struct list_head *_io_jobs;
extern struct list_head *_md_io_jobs;
extern struct list_head *_md_complete_jobs;

static void flashcache_zero_stats(struct cache_c *dmc);

struct flashcache_control_s {
	unsigned long synch_flags;
};

struct flashcache_control_s *flashcache_control;

/* Bit offsets for wait_on_bit_lock() */
#define FLASHCACHE_UPDATE_LIST		0

static int flashcache_notify_reboot(struct notifier_block *this,
				    unsigned long code, void *x);
static void flashcache_sync_for_remove(struct cache_c *dmc);

static int
flashcache_wait_schedule(void *unused)
{
	schedule();
	return 0;
}

static int 
flashcache_sync_sysctl_handler(ctl_table *table, int write,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
			       struct file *file, 
#endif
			       void __user *buffer, 
			       size_t *length, loff_t *ppos)
{
	struct cache_c *dmc;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
	proc_dointvec_minmax(table, write, file, buffer, length, ppos);
#else
	proc_dointvec_minmax(table, write, buffer, length, ppos);
#endif
	if (write) {
		if (sysctl_flashcache_sync) {
			sysctl_flashcache_stop_sync = 0;
			(void)wait_on_bit_lock(&flashcache_control->synch_flags, 
					       FLASHCACHE_UPDATE_LIST,
					       flashcache_wait_schedule, 
					       TASK_UNINTERRUPTIBLE);
			for (dmc = cache_list_head ; 
			     dmc != NULL ; 
			     dmc = dmc->next_cache) {
				cancel_delayed_work(&dmc->delayed_clean);
				flush_scheduled_work();
				flashcache_sync_all(dmc);
			}
			clear_bit(FLASHCACHE_UPDATE_LIST, &flashcache_control->synch_flags);
			smp_mb__after_clear_bit();
			wake_up_bit(&flashcache_control->synch_flags, FLASHCACHE_UPDATE_LIST);
		}
	}
	return 0;
}

static int 
flashcache_zerostats_sysctl_handler(ctl_table *table, int write,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
				    struct file *file, 
#endif
				    void __user *buffer, 
				    size_t *length, loff_t *ppos)
{
	struct cache_c *dmc;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
	proc_dointvec_minmax(table, write, file, buffer, length, ppos);
#else
	proc_dointvec_minmax(table, write, buffer, length, ppos);
#endif
	if (write) {
		if (sysctl_flashcache_zerostats) {
			(void)wait_on_bit_lock(&flashcache_control->synch_flags, 
					       FLASHCACHE_UPDATE_LIST,
					       flashcache_wait_schedule, 
					       TASK_UNINTERRUPTIBLE);
			for (dmc = cache_list_head ; 
			     dmc != NULL ; 
			     dmc = dmc->next_cache)
				flashcache_zero_stats(dmc);
			clear_bit(FLASHCACHE_UPDATE_LIST, &flashcache_control->synch_flags);
			smp_mb__after_clear_bit();
			wake_up_bit(&flashcache_control->synch_flags, FLASHCACHE_UPDATE_LIST);
		}
	}
	return 0;
}

static int
flashcache_dirty_thresh_sysctl_handler(ctl_table *table, int write,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
				       struct file *file, 
#endif
				       void __user *buffer, 
				       size_t *length, loff_t *ppos)
{
	struct cache_c *dmc;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
        proc_dointvec_minmax(table, write, file, buffer, length, ppos);
#else
        proc_dointvec_minmax(table, write, buffer, length, ppos);
#endif
	if (write) {
		if (sysctl_flashcache_dirty_thresh > DIRTY_THRESH_MAX ||
		    sysctl_flashcache_dirty_thresh < DIRTY_THRESH_MIN)
			sysctl_flashcache_dirty_thresh = DIRTY_THRESH_DEF;
		(void)wait_on_bit_lock(&flashcache_control->synch_flags, 
				       FLASHCACHE_UPDATE_LIST,
				       flashcache_wait_schedule, 
				       TASK_UNINTERRUPTIBLE);
		for (dmc = cache_list_head ; 
		     dmc != NULL ; 
		     dmc = dmc->next_cache)
			dmc->dirty_thresh_set = 
				(dmc->assoc * sysctl_flashcache_dirty_thresh) / 100;
		clear_bit(FLASHCACHE_UPDATE_LIST, &flashcache_control->synch_flags);
		smp_mb__after_clear_bit();
		wake_up_bit(&flashcache_control->synch_flags, FLASHCACHE_UPDATE_LIST);		
	}
	return 0;
}

static int
flashcache_max_clean_ios_total_sysctl_handler(ctl_table *table, int write,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
					      struct file *file, 
#endif
					      void __user *buffer, 
					      size_t *length, loff_t *ppos)
{
	struct cache_c *dmc;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
        proc_dointvec_minmax(table, write, file, buffer, length, ppos);
#else
        proc_dointvec_minmax(table, write, buffer, length, ppos);
#endif
	if (write) {
		(void)wait_on_bit_lock(&flashcache_control->synch_flags, 
				       FLASHCACHE_UPDATE_LIST,
				       flashcache_wait_schedule, 
				       TASK_UNINTERRUPTIBLE);
		for (dmc = cache_list_head ; 
		     dmc != NULL ; 
		     dmc = dmc->next_cache)
			dmc->max_clean_ios_total = sysctl_max_clean_ios_total;
		clear_bit(FLASHCACHE_UPDATE_LIST, &flashcache_control->synch_flags);
		smp_mb__after_clear_bit();
		wake_up_bit(&flashcache_control->synch_flags, 
			    FLASHCACHE_UPDATE_LIST);
	}
	return 0;
}

static int
flashcache_max_clean_ios_set_sysctl_handler(ctl_table *table, int write,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
					    struct file *file, 
#endif
					    void __user *buffer, 
					    size_t *length, loff_t *ppos)
{
	struct cache_c *dmc;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
        proc_dointvec_minmax(table, write, file, buffer, length, ppos);
#else
        proc_dointvec_minmax(table, write, buffer, length, ppos);
#endif
	if (write) {
		(void)wait_on_bit_lock(&flashcache_control->synch_flags, FLASHCACHE_UPDATE_LIST,
				       flashcache_wait_schedule, TASK_UNINTERRUPTIBLE);
		for (dmc = cache_list_head ; 
		     dmc != NULL ; 
		     dmc = dmc->next_cache)
			dmc->max_clean_ios_set = sysctl_max_clean_ios_set;
		clear_bit(FLASHCACHE_UPDATE_LIST, &flashcache_control->synch_flags);
		smp_mb__after_clear_bit();
		wake_up_bit(&flashcache_control->synch_flags, FLASHCACHE_UPDATE_LIST);
	}
	return 0;
}

static ctl_table flashcache_table[] = {
	{
		.ctl_name	= FLASHCACHE_WB_SYNC,
		.procname	= "do_sync",
		.data		= &sysctl_flashcache_sync,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &flashcache_sync_sysctl_handler,
		.strategy	= &sysctl_intvec,
	},
	{
		.ctl_name	= FLASHCACHE_WB_STOP_SYNC,
		.procname	= "stop_sync",
		.data		= &sysctl_flashcache_stop_sync,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= FLASHCACHE_WB_DIRTY_THRESH,
		.procname	= "dirty_thresh_pct",
		.data		= &sysctl_flashcache_dirty_thresh,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &flashcache_dirty_thresh_sysctl_handler,
		.strategy	= &sysctl_intvec,
	},
	{
		.ctl_name	= FLASHCACHE_WB_DEBUG,
		.procname	= "debug",
		.data		= &sysctl_flashcache_debug,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= FLASHCACHE_WB_MAX_CLEAN_IOS_TOTAL,
		.procname	= "max_clean_ios_total",
		.data		= &sysctl_max_clean_ios_total,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &flashcache_max_clean_ios_total_sysctl_handler,
		.strategy	= &sysctl_intvec,
	},
	{
		.ctl_name	= FLASHCACHE_WB_MAX_CLEAN_IOS_SET,
		.procname	= "max_clean_ios_set",
		.data		= &sysctl_max_clean_ios_set,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &flashcache_max_clean_ios_set_sysctl_handler,
		.strategy	= &sysctl_intvec,
	},
	{
		.ctl_name	= FLASHCACHE_WB_DO_NC_EXPIRY,
		.procname	= "do_nc_pid_expiry",
		.data		= &sysctl_nc_pid_do_expiry,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= FLASHCACHE_WB_MAX_NC_PIDS,
		.procname	= "max_nc_pids",
		.data		= &sysctl_flashcache_max_nc_pids,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= FLASHCACHE_WB_MAX_NC_PID_EXPIRY,
		.procname	= "nc_pid_expiry_secs",
		.data		= &sysctl_nc_pid_expiry_check,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= FLASHCACHE_WB_RECLAIM_POLICY,
		.procname	= "reclaim_policy",
		.data		= &sysctl_flashcache_reclaim_policy,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= FLASHCACHE_WB_WRITE_MERGE,
		.procname	= "write_merge",
		.data		= &sysctl_flashcache_write_merge,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.ctl_name	= FLASHCACHE_WB_ZERO_STATS,
		.procname	= "zero_stats",
		.data		= &sysctl_flashcache_zerostats,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &flashcache_zerostats_sysctl_handler,
		.strategy	= &sysctl_intvec,
	},
#ifdef notdef
	/* Disable this for all except devel builds */
	{
		.ctl_name	= FLASHCACHE_WB_ERROR_INJECT,
		.procname	= "error_inject",
		.data		= &sysctl_flashcache_error_inject,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif
	{
		.ctl_name	= FLASHCACHE_WB_DO_FAST_REMOVE,
		.procname	= "fast_remove",
		.data		= &sysctl_flashcache_fast_remove,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{ .ctl_name = 0 }
};

static ctl_table flashcache_dir_table[] = {
	{
		.ctl_name	= DEV_RAID,
		.procname	= "flashcache",
		.maxlen		= 0,
		.mode		= S_IRUGO|S_IXUGO,
		.child		= flashcache_table,
	},
	{ .ctl_name = 0 }
};

static ctl_table flashcache_root_table[] = {
	{
		.ctl_name	= CTL_DEV,
		.procname	= "dev",
		.maxlen		= 0,
		.mode		= 0555,
		.child		= flashcache_dir_table,
	},
	{ .ctl_name = 0 }
};

static int 
flashcache_jobs_init(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	_job_cache = kmem_cache_create("kcached-jobs",
	                               sizeof(struct kcached_job),
	                               __alignof__(struct kcached_job),
	                               0, NULL, NULL);
#else
	_job_cache = kmem_cache_create("kcached-jobs",
	                               sizeof(struct kcached_job),
	                               __alignof__(struct kcached_job),
	                               0, NULL);
#endif
	if (!_job_cache)
		return -ENOMEM;

	_job_pool = mempool_create(MIN_JOBS, mempool_alloc_slab,
	                           mempool_free_slab, _job_cache);
	if (!_job_pool) {
		kmem_cache_destroy(_job_cache);
		return -ENOMEM;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	_pending_job_cache = kmem_cache_create("pending-jobs",
					       sizeof(struct pending_job),
					       __alignof__(struct pending_job),
					       0, NULL, NULL);
#else
	_pending_job_cache = kmem_cache_create("pending-jobs",
					       sizeof(struct pending_job),
					       __alignof__(struct pending_job),
					       0, NULL);
#endif
	if (!_pending_job_cache) {
		mempool_destroy(_job_pool);
		kmem_cache_destroy(_job_cache);
		return -ENOMEM;
	}

	_pending_job_pool = mempool_create(MIN_JOBS, mempool_alloc_slab,
					   mempool_free_slab, _pending_job_cache);
	if (!_pending_job_pool) {
		kmem_cache_destroy(_pending_job_cache);
		mempool_destroy(_job_pool);
		kmem_cache_destroy(_job_cache);
		return -ENOMEM;
	}

	return 0;
}

static void 
flashcache_jobs_exit(void)
{
	VERIFY(flashcache_pending_empty());
	VERIFY(flashcache_io_empty());
	VERIFY(flashcache_md_io_empty());
	VERIFY(flashcache_md_complete_empty());

	mempool_destroy(_job_pool);
	kmem_cache_destroy(_job_cache);
	_job_pool = NULL;
	_job_cache = NULL;
	mempool_destroy(_pending_job_pool);
	kmem_cache_destroy(_pending_job_cache);
	_pending_job_pool = NULL;
	_pending_job_cache = NULL;
}

static int 
flashcache_kcached_init(struct cache_c *dmc)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	int r;

	r = dm_io_get(FLASHCACHE_ASYNC_SIZE);
	if (r) {
		DMERR("flashcache_kcached_init: Could not resize dm io pool");
		return r;
	}
#endif
	init_waitqueue_head(&dmc->destroyq);
	atomic_set(&dmc->nr_jobs, 0);
	atomic_set(&dmc->fast_remove_in_prog, 0);
	return 0;
}

static void
flashcache_kcached_client_destroy(struct cache_c *dmc)
{
	/* Wait for all IOs */
	wait_event(dmc->destroyq, !atomic_read(&dmc->nr_jobs));	
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	dm_io_put(FLASHCACHE_ASYNC_SIZE);
#endif
}

/*
 * Write out the metadata one sector at a time.
 * Then dump out the superblock.
 */
static int 
flashcache_md_store(struct cache_c *dmc)
{
	struct flash_cacheblock *meta_data_cacheblock, *next_ptr;
	struct flash_superblock *header;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	struct io_region where;
#else
	struct dm_io_region where;
#endif
	int i, j;
	int next_sector;
	int num_valid = 0, num_dirty = 0;
	int error;
	int write_errors = 0;

	meta_data_cacheblock = (struct flash_cacheblock *)vmalloc(512);
	if (!meta_data_cacheblock) {
		DMERR("flashcache_md_store: Unable to allocate memory");
		DMERR("flashcache_md_store: Could not write out cache metadata !");
		return 1;
	}	
	next_ptr = meta_data_cacheblock;
	j = MD_BLOCKS_PER_SECTOR;
	next_sector = 1;
	where.bdev = dmc->cache_dev->bdev;
	where.count = 1;

	for (i = 0 ; i < dmc->size ; i++) {
		if (dmc->cache[i].cache_state & VALID)
			num_valid++;
		if (dmc->cache[i].cache_state & DIRTY)
			num_dirty++;
		next_ptr->dbn = dmc->cache[i].dbn;
#ifdef FLASHCACHE_DO_CHECKSUMS
		next_ptr->checksum = dmc->cache[i].checksum;
#endif
		next_ptr->cache_state = dmc->cache[i].cache_state & 
			(INVALID | VALID | DIRTY);
		next_ptr++;
		j--;
		if (j == 0) {
			/* 
			 * Filled the sector, write it out 
			 */
			where.sector = next_sector++;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
			error = flashcache_dm_io_sync_vm(&where, WRITE, meta_data_cacheblock);
#else
			error = flashcache_dm_io_sync_vm(dmc, &where, WRITE, meta_data_cacheblock);
#endif
			if (error) {
				write_errors++;
				DMERR("flashcache_md_store: Could not write out cache metadata sector %lu error %d !",
				      where.sector, error);
			}
			j = MD_BLOCKS_PER_SECTOR;
			next_ptr = meta_data_cacheblock;
		}
	}
	if (next_ptr != meta_data_cacheblock) {
		/* Write the remaining last sector out */
		where.sector = next_sector++;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
		error = flashcache_dm_io_sync_vm(&where, WRITE, meta_data_cacheblock);
#else
		error = flashcache_dm_io_sync_vm(dmc, &where, WRITE, meta_data_cacheblock);
#endif
		if (error) {
			write_errors++;
				DMERR("flashcache_md_store: Could not write out cache metadata sector %lu error %d !",
				      where.sector, error);
		}
	}

	header = (struct flash_superblock *)meta_data_cacheblock;
	
	/* Write the header out last */
	if (write_errors == 0) {
		if (num_dirty == 0)
			header->cache_sb_state = CACHE_MD_STATE_CLEAN;
		else
			header->cache_sb_state = CACHE_MD_STATE_FASTCLEAN;			
	} else
		header->cache_sb_state = CACHE_MD_STATE_UNSTABLE;
	header->block_size = dmc->block_size;
	header->size = dmc->size;
	header->assoc = dmc->assoc;
	strncpy(header->disk_devname, dmc->disk_devname, DEV_PATHLEN);
	strncpy(header->cache_devname, dmc->cache_devname, DEV_PATHLEN);
	header->cache_devsize = to_sector(dmc->cache_dev->bdev->bd_inode->i_size);
	header->disk_devsize = to_sector(dmc->disk_dev->bdev->bd_inode->i_size);
	header->cache_version = FLASHCACHE_VERSION;

	DPRINTK("Store metadata to disk: block size(%u), cache size(%llu)" \
	        "associativity(%u)",
	        header->block_size, header->size,
	        header->assoc);

	where.sector = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	error = flashcache_dm_io_sync_vm(&where, WRITE, meta_data_cacheblock);
#else
	error = flashcache_dm_io_sync_vm(dmc, &where, WRITE, meta_data_cacheblock);
#endif
	if (error) {
		write_errors++;
		DMERR("flashcache_md_store: Could not write out cache metadata superblock %lu error %d !",
		      where.sector, error);
	}

	vfree((void *)meta_data_cacheblock);

	if (write_errors == 0)
		DMINFO("Cache metadata saved to disk");
	else {
		DMINFO("CRITICAL : There were %d errors in saving cache metadata saved to disk", 
		       write_errors);
		if (num_dirty)
			DMINFO("CRITICAL : You have likely lost %d dirty blocks", num_dirty);
	}

	DMINFO("flashcache_md_store: valid blocks = %d dirty blocks = %d md_sectors = %d\n", 
	       num_valid, num_dirty, dmc->md_sectors);

	return 0;
}

static int 
flashcache_md_create(struct cache_c *dmc, int force)
{
	struct flash_cacheblock *meta_data_cacheblock, *next_ptr;
	struct flash_superblock *header;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	struct io_region where;
#else
	struct dm_io_region where;
#endif
	int i, j, error;
	int next_sector;
	sector_t cache_size, dev_size;
	sector_t order;
	
	header = (struct flash_superblock *)vmalloc(512);
	if (!header) {
		DMERR("flashcache_md_create: Unable to allocate sector");
		return 1;
	}
	where.bdev = dmc->cache_dev->bdev;
	where.sector = 0;
	where.count = 1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	error = flashcache_dm_io_sync_vm(&where, READ, header);
#else
	error = flashcache_dm_io_sync_vm(dmc, &where, READ, header);
#endif
	if (error) {
		vfree((void *)header);
		DMERR("flashcache_md_create: Could not read cache superblock sector %lu error %d !",
		      where.sector, error);
		return 1;
	}

	if (!force &&
	    ((header->cache_sb_state == CACHE_MD_STATE_DIRTY) ||
	     (header->cache_sb_state == CACHE_MD_STATE_CLEAN) ||
	     (header->cache_sb_state == CACHE_MD_STATE_FASTCLEAN))) {
		vfree((void *)header);
		DMERR("flashcache_md_create: Existing Cache Detected, use force to re-create");
		return 1;
	}

	/* Compute the size of the metadata, including header. 
	   Note dmc->size is in raw sectors */
	dmc->md_sectors = INDEX_TO_MD_SECTOR(dmc->size / dmc->block_size) + 1 + 1;
	dmc->size -= dmc->md_sectors;	/* total sectors available for cache */
	dmc->size /= dmc->block_size;
	dmc->size = (dmc->size / dmc->assoc) * dmc->assoc;	
	/* Recompute since dmc->size was possibly trunc'ed down */
	dmc->md_sectors = INDEX_TO_MD_SECTOR(dmc->size) + 1 + 1;

	DMINFO("flashcache_md_create: md_sectors = %d\n", dmc->md_sectors);

	dev_size = to_sector(dmc->cache_dev->bdev->bd_inode->i_size);
	cache_size = dmc->md_sectors + (dmc->size * dmc->block_size);
	if (cache_size > dev_size) {
		DMERR("Requested cache size exceeds the cache device's capacity" \
		      "(%lu>%lu)",
  		      cache_size, dev_size);
		vfree((void *)header);
		return 1;
	}

	order = dmc->size * sizeof(struct cacheblock);
	DMINFO("Allocate %luKB (%luB per) mem for %lu-entry cache" \
	       "(capacity:%luMB, associativity:%u, block size:%u " \
	       "sectors(%uKB))",
	       order >> 10, sizeof(struct cacheblock), dmc->size,
	       cache_size >> (20-SECTOR_SHIFT), dmc->assoc, dmc->block_size,
	       dmc->block_size >> (10-SECTOR_SHIFT));
	dmc->cache = (struct cacheblock *)vmalloc(order);
	if (!dmc->cache) {
		vfree((void *)header);
		DMERR("flashcache_md_create: Unable to allocate cache md");
		return 1;
	}
	
	/* Initialize the cache structs */
	for (i = 0; i < dmc->size ; i++) {
		dmc->cache[i].dbn = 0;
#ifdef FLASHCACHE_DO_CHECKSUMS
		dmc->cache[i].checksum = 0;
#endif
		dmc->cache[i].cache_state = INVALID;
		dmc->cache[i].head = NULL;
		dmc->cache[i].nr_queued = 0;
	}

	meta_data_cacheblock = (struct flash_cacheblock *)header;
	next_ptr = meta_data_cacheblock;
	j = MD_BLOCKS_PER_SECTOR;
	next_sector = 1;

	for (i = 0 ; i < dmc->size ; i++) {
		next_ptr->dbn = dmc->cache[i].dbn;
#ifdef FLASHCACHE_DO_CHECKSUMS
		next_ptr->checksum = dmc->cache[i].checksum;
#endif
		next_ptr->cache_state = dmc->cache[i].cache_state & 
			(INVALID | VALID | DIRTY);
		next_ptr++;
		j--;
		if (j == 0) {
			/* 
			 * Filled the sector, write it out 
			 */
			where.sector = next_sector++;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
			error = flashcache_dm_io_sync_vm(&where, WRITE, 
							 meta_data_cacheblock);
#else
			error = flashcache_dm_io_sync_vm(dmc, &where, WRITE, 
							 meta_data_cacheblock);
#endif
			if (error) {
				vfree((void *)header);
				vfree(dmc->cache);
				DMERR("flashcache_md_create: Could not write  cache metadata sector %lu error %d !",
				      where.sector, error);
				return 1;				
			}
			j = MD_BLOCKS_PER_SECTOR;
			next_ptr = meta_data_cacheblock;
		}
	}
	if (next_ptr != meta_data_cacheblock) {
		/* Write the remaining last sector out */
		where.sector = next_sector++;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
		error = flashcache_dm_io_sync_vm(&where, WRITE, meta_data_cacheblock);
#else
		error = flashcache_dm_io_sync_vm(dmc, &where, WRITE, meta_data_cacheblock);
#endif
		if (error) {
			vfree((void *)header);
			vfree(dmc->cache);
			DMERR("flashcache_md_create: Could not write  cache metadata sector %lu error %d !",
			      where.sector, error);
			return 1;		
		}
	}

	/* Write the header */
	header->cache_sb_state = CACHE_MD_STATE_DIRTY;
	header->block_size = dmc->block_size;
	header->size = dmc->size;
	header->assoc = dmc->assoc;
	strncpy(header->disk_devname, dmc->disk_devname, DEV_PATHLEN);
	strncpy(header->cache_devname, dmc->cache_devname, DEV_PATHLEN);
	header->cache_devsize = to_sector(dmc->cache_dev->bdev->bd_inode->i_size);
	header->disk_devsize = to_sector(dmc->disk_dev->bdev->bd_inode->i_size);
	header->cache_version = FLASHCACHE_VERSION;

	where.sector = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	error = flashcache_dm_io_sync_vm(&where, WRITE, header);
#else
	error = flashcache_dm_io_sync_vm(dmc, &where, WRITE, header);
#endif
	if (error) {
		vfree((void *)header);
		vfree(dmc->cache);
		DMERR("flashcache_md_create: Could not write cache superblock sector %lu error %d !",
		      where.sector, error);
		return 1;		
	}

	vfree((void *)header);

	return 0;
}

static int 
flashcache_md_load(struct cache_c *dmc)
{
	struct flash_cacheblock *meta_data_cacheblock, *next_ptr;
	struct flash_superblock *header;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	struct io_region where;
#else
	struct dm_io_region where;
#endif
	int i, j;
	int next_sector;
	int size, slots_read;
	int clean_shutdown;
	int dirty_loaded = 0;
	sector_t order, data_size;
	int num_valid = 0;
	int error;
	void *block;
	
	header = (struct flash_superblock *)vmalloc(512);
	if (!header) {
		DMERR("flashcache_md_load: Unable to allocate memory");
		return 1;
	}
	where.bdev = dmc->cache_dev->bdev;
	where.sector = 0;
	where.count = 1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	error = flashcache_dm_io_sync_vm(&where, READ, header);
#else
	error = flashcache_dm_io_sync_vm(dmc, &where, READ, header);
#endif
	if (error) {
		vfree((void *)header);
		DMERR("flashcache_md_load: Could not read cache superblock sector %lu error %d!",
		      where.sector, error);
		return 1;
	}

	DPRINTK("Loaded cache conf: block size(%u), cache size(%llu), " \
	        "associativity(%u)",
	        header->block_size, header->size,
	        header->assoc);

	if (!((header->cache_sb_state == CACHE_MD_STATE_DIRTY) ||
	      (header->cache_sb_state == CACHE_MD_STATE_CLEAN) ||
	      (header->cache_sb_state == CACHE_MD_STATE_FASTCLEAN))) {
		vfree((void *)header);
		DMERR("flashcache_md_load: Corrupt Cache Superblock");
		return 1;
	}

	if (header->cache_sb_state == CACHE_MD_STATE_DIRTY) {
		DMINFO("Unclean Shutdown Detected");
		printk(KERN_ALERT "Only DIRTY blocks exist in cache");
		clean_shutdown = 0;
	} else if (header->cache_sb_state == CACHE_MD_STATE_CLEAN) {
		DMINFO("Slow (clean) Shutdown Detected");
		printk(KERN_ALERT "Only CLEAN blocks exist in cache");
		clean_shutdown = 1;
	} else {
		DMINFO("Fast (clean) Shutdown Detected");
		printk(KERN_ALERT "Both CLEAN and DIRTY blocks exist in cache");
		clean_shutdown = 1;
	}

	dmc->block_size = header->block_size;
	dmc->block_shift = ffs(dmc->block_size) - 1;
	dmc->block_mask = dmc->block_size - 1;
	dmc->size = header->size;
	dmc->assoc = header->assoc;
	dmc->consecutive_shift = ffs(dmc->assoc) - 1;
	dmc->md_sectors = INDEX_TO_MD_SECTOR(dmc->size) + 1 + 1;

	DMINFO("flashcache_md_load: md_sectors = %d\n", dmc->md_sectors);

	data_size = dmc->size * dmc->block_size;
	
	order = dmc->size * sizeof(struct cacheblock);
	DMINFO("Allocate %luKB (%ldB per) mem for %lu-entry cache" \
	       "(capacity:%luMB, associativity:%u, block size:%u " \
	       "sectors(%uKB))",
	       order >> 10, sizeof(struct cacheblock), dmc->size,
	       (dmc->md_sectors + data_size) >> (20-SECTOR_SHIFT), 
	       dmc->assoc, dmc->block_size,
	       dmc->block_size >> (10-SECTOR_SHIFT));
	dmc->cache = (struct cacheblock *)vmalloc(order);
	if (!dmc->cache) {
		DMERR("load_metadata: Unable to allocate memory");
		vfree((void *)header);
		return 1;
	}

	block = vmalloc(dmc->block_size * 512);
	if (!block) {
		DMERR("load_metadata: Unable to allocate memory");
			vfree((void *)header);
			vfree(dmc->cache);
			DMERR("flashcache_md_load: Could not read cache metadata sector %lu !",
			      where.sector);
			return 1;
	}
	
	/* 
	 * Read 1 sector of the metadata at a time and load up the
	 * incore metadata struct.
	 */
	meta_data_cacheblock = (struct flash_cacheblock *)header;
	next_sector = 1;
	size = dmc->size;
	i = 0;
	while (size > 0) {
		if (size > MD_BLOCKS_PER_SECTOR)
			slots_read = MD_BLOCKS_PER_SECTOR;
		else 
			slots_read = size;
		where.sector = next_sector++;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
		error = flashcache_dm_io_sync_vm(&where, READ, meta_data_cacheblock);
#else
		error = flashcache_dm_io_sync_vm(dmc, &where, READ, meta_data_cacheblock);
#endif
		if (error) {
			vfree((void *)header);
			vfree(dmc->cache);
			vfree(block);
			DMERR("flashcache_md_load: Could not read cache metadata sector %lu error %d !",
			      where.sector, error);
			return 1;
		}
		next_ptr = meta_data_cacheblock;
		for (j = 0 ; j < slots_read ; j++) {
			dmc->cache[i].nr_queued = 0;
			dmc->cache[i].head = NULL;
			/* 
			 * If unclean shutdown, only the DIRTY blocks are loaded.
			 */
			if (clean_shutdown || (next_ptr->cache_state & DIRTY)) {
				if (next_ptr->cache_state & DIRTY)
					dirty_loaded++;
				dmc->cache[i].cache_state = next_ptr->cache_state;
				VERIFY((dmc->cache[i].cache_state & (VALID | INVALID)) 
				       != (VALID | INVALID));
				if (dmc->cache[i].cache_state & VALID)
					num_valid++;
				dmc->cache[i].dbn = next_ptr->dbn;
#ifdef FLASHCACHE_DO_CHECKSUMS
				if (clean_shutdown)
					dmc->cache[i].checksum = next_ptr->checksum;
				else {
					error = flashcache_read_compute_checksum(dmc, i, block);
					if (error) {
						vfree((void *)header);
						vfree(dmc->cache);
						vfree(block);
						DMERR("flashcache_md_load: Could not read cache block sector %lu error %d !",
						      dmc->cache[i].dbn, error);
						return 1;				
					}						
				}
#endif
			} else {
				dmc->cache[i].cache_state = INVALID;
				dmc->cache[i].dbn = 0;
#ifdef FLASHCACHE_DO_CHECKSUMS
				dmc->cache[i].checksum = 0;
#endif
			}
			next_ptr++;
			i++;
		}
		size -= slots_read;
	}

	/* Before we finish loading, we need to dirty the suprtblock and 
	   write it out */
	header->size = dmc->size;
	header->block_size = dmc->block_size;
	header->assoc = dmc->assoc;
	header->cache_sb_state = CACHE_MD_STATE_DIRTY;
	strncpy(header->disk_devname, dmc->disk_devname, DEV_PATHLEN);
	strncpy(header->cache_devname, dmc->cache_devname, DEV_PATHLEN);
	header->cache_devsize = to_sector(dmc->cache_dev->bdev->bd_inode->i_size);
	header->disk_devsize = to_sector(dmc->disk_dev->bdev->bd_inode->i_size);
	header->cache_version = FLASHCACHE_VERSION;

	where.sector = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	error = flashcache_dm_io_sync_vm(&where, WRITE, header);
#else
	error = flashcache_dm_io_sync_vm(dmc, &where, WRITE, header);
#endif
	if (error) {
		vfree((void *)header);
		vfree(dmc->cache);
		vfree(block);
		DMERR("flashcache_md_load: Could not write cache superblock sector %lu error %d !",
		      where.sector, error);
		return 1;		
	}

	vfree((void *)header);
	vfree(block);

	DMINFO("flashcache_md_load: Cache metadata loaded from disk with %d valid %d DIRTY blocks", 
	       num_valid, dirty_loaded);

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void
flashcache_clean_all_sets(void *data)
{
	struct cache_c *dmc = (struct cache_c *)data;
#else
static void
flashcache_clean_all_sets(struct work_struct *work)
{
	struct cache_c *dmc = container_of(work, struct cache_c, 
					   delayed_clean.work);
#endif
	int i;
	
	for (i = 0 ; i < (dmc->size >> dmc->consecutive_shift) ; i++)
		flashcache_clean_set(dmc, i);
}

/*
 * Construct a cache mapping.
 *  arg[0]: path to source device
 *  arg[1]: path to cache device
 *  arg[2]: cache persistence (if set, cache conf is loaded from disk)
 * Cache configuration parameters (if not set, default values are used.
 *  arg[3]: cache block size (in sectors)
 *  arg[4]: cache size (in blocks)
 *  arg[5]: cache associativity
 */
int 
flashcache_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct cache_c *dmc;
	unsigned int consecutive_blocks;
	sector_t i, order;
	int r = -EINVAL;
	int persistence = 0;

	if (argc < 2) {
		ti->error = "flashcache: Need at least 2 arguments";
		goto bad;
	}

	dmc = kzalloc(sizeof(*dmc), GFP_KERNEL);
	if (dmc == NULL) {
		ti->error = "flashcache: Failed to allocate cache context";
		r = ENOMEM;
		goto bad;
	}

	dmc->tgt = ti;

	r = dm_get_device(ti, argv[0], 0, ti->len,
			  dm_table_get_mode(ti->table), &dmc->disk_dev);
	if (r) {
		ti->error = "flashcache: Source device lookup failed";
		goto bad1;
	}
	strncpy(dmc->disk_devname, argv[0], DEV_PATHLEN);

	r = dm_get_device(ti, argv[1], 0, 0,
			  dm_table_get_mode(ti->table), &dmc->cache_dev);
	if (r) {
		ti->error = "flashcache: Cache device lookup failed";
		goto bad2;
	}
	strncpy(dmc->cache_devname, argv[1], DEV_PATHLEN);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	dmc->io_client = dm_io_client_create(FLASHCACHE_COPY_PAGES);
	if (IS_ERR(dmc->io_client)) {
		r = PTR_ERR(dmc->io_client);
		ti->error = "Failed to create io client\n";
		goto bad3;
	}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	r = kcopyd_client_create(FLASHCACHE_COPY_PAGES, &dmc->kcp_client);
	if (r) {
		ti->error = "Failed to initialize kcopyd client\n";
		goto bad3;
	}
#else
	r = dm_kcopyd_client_create(FLASHCACHE_COPY_PAGES, &dmc->kcp_client);
	if (r) {
		ti->error = "Failed to initialize kcopyd client\n";
		dm_io_client_destroy(dmc->io_client);
		goto bad3;
	}
#endif

	r = flashcache_kcached_init(dmc);
	if (r) {
		ti->error = "Failed to initialize kcached";
		goto bad4;
	}

	if (argc >= 3) {
		if (sscanf(argv[2], "%u", &persistence) != 1) {
			ti->error = "flashcache: sscanf failed, invalid cache persistence";
			r = -EINVAL;
			goto bad5;
		}
		if (persistence < CACHE_RELOAD || persistence > CACHE_FORCECREATE) {
			DMERR("persistence = %d", persistence);
			ti->error = "flashcache: Invalid cache persistence";
			r = -EINVAL;
			goto bad5;
		}			
	}
	if (persistence == CACHE_RELOAD) {
		if (flashcache_md_load(dmc)) {
			ti->error = "flashcache: Cache reload failed";
			r = -EINVAL;
			goto bad5;
		}
		goto init; /* Skip reading cache parameters from command line */
	}

	if (argc >= 4) {
		if (sscanf(argv[3], "%u", &dmc->block_size) != 1) {
			ti->error = "flashcache: Invalid block size";
			r = -EINVAL;
			goto bad5;
		}
		if (!dmc->block_size || (dmc->block_size & (dmc->block_size - 1))) {
			ti->error = "flashcache: Invalid block size";
			r = -EINVAL;
			goto bad5;
		}
	} else
		dmc->block_size = DEFAULT_BLOCK_SIZE;
	dmc->block_shift = ffs(dmc->block_size) - 1;
	dmc->block_mask = dmc->block_size - 1;

	/* dmc->size is specified in sectors here, and converted to blocks later */
	if (argc >= 5) {
		if (sscanf(argv[4], "%lu", &dmc->size) != 1) {
			ti->error = "flashcache: Invalid cache size";
			r = -EINVAL;
			goto bad5;
		}
	} else {
		dmc->size = to_sector(dmc->cache_dev->bdev->bd_inode->i_size);
	}

	if (argc >= 6) {
		if (sscanf(argv[5], "%u", &dmc->assoc) != 1) {
			ti->error = "flashcache: Invalid cache associativity";
			r = -EINVAL;
			goto bad5;
		}
		if (!dmc->assoc || (dmc->assoc & (dmc->assoc - 1)) ||
		    dmc->assoc > FLASHCACHE_MAX_ASSOC ||
		    dmc->size < dmc->assoc) {
			ti->error = "flashcache: Invalid cache associativity";
			r = -EINVAL;
			goto bad5;
		}
	} else
		dmc->assoc = DEFAULT_CACHE_ASSOC;
	
	consecutive_blocks = dmc->assoc;
	dmc->consecutive_shift = ffs(consecutive_blocks) - 1;

	if (persistence == CACHE_CREATE) {
		if (flashcache_md_create(dmc, 0)) {
			ti->error = "flashcache: Cache Create Failed";
			r = -EINVAL;
			goto bad5;
		}
	} else {
		if (flashcache_md_create(dmc, 1)) {
			ti->error = "flashcache: Cache Force Create Failed";
			r = -EINVAL;
			goto bad5;
		}
	}

init:
	order = (dmc->size >> dmc->consecutive_shift) * sizeof(struct cache_set);
	dmc->cache_sets = (struct cache_set *)vmalloc(order);
	if (!dmc->cache_sets) {
		ti->error = "Unable to allocate memory";
		r = -ENOMEM;
		vfree((void *)dmc->cache);
		goto bad5;
	}				

	for (i = 0 ; i < (dmc->size >> dmc->consecutive_shift) ; i++) {
		dmc->cache_sets[i].set_fifo_next = i * dmc->assoc;
		dmc->cache_sets[i].set_clean_next = i * dmc->assoc;
		dmc->cache_sets[i].nr_dirty = 0;
		dmc->cache_sets[i].clean_inprog = 0;
		dmc->cache_sets[i].lru_tail = FLASHCACHE_LRU_NULL;
		dmc->cache_sets[i].lru_head = FLASHCACHE_LRU_NULL;
	}

	/* Push all blocks into the set specific LRUs */
	for (i = 0 ; i < dmc->size ; i++) {
		dmc->cache[i].lru_prev = FLASHCACHE_LRU_NULL;
		dmc->cache[i].lru_next = FLASHCACHE_LRU_NULL;
		flashcache_reclaim_lru_movetail(dmc, i);
	}

	order = (dmc->md_sectors - 1) * sizeof(struct cache_md_sector_head);
	dmc->md_sectors_buf = (struct cache_md_sector_head *)vmalloc(order);
	if (!dmc->md_sectors_buf) {
		ti->error = "Unable to allocate memory";
		r = -ENOMEM;
		vfree((void *)dmc->cache);
		vfree((void *)dmc->cache_sets);
		goto bad5;
	}		

	for (i = 0 ; i < dmc->md_sectors - 1 ; i++) {
		dmc->md_sectors_buf[i].nr_in_prog = 0;
		dmc->md_sectors_buf[i].pending_jobs = NULL;
	}

	spin_lock_init(&dmc->cache_spin_lock);

	dmc->sync_index = 0;
	dmc->clean_inprog = 0;

	ti->split_io = dmc->block_size;
	ti->private = dmc;

	/* Cleaning Thresholds */
	dmc->dirty_thresh_set = (dmc->assoc * sysctl_flashcache_dirty_thresh) / 100;
	dmc->max_clean_ios_total = sysctl_max_clean_ios_total;
	dmc->max_clean_ios_set = sysctl_max_clean_ios_set;

	(void)wait_on_bit_lock(&flashcache_control->synch_flags, FLASHCACHE_UPDATE_LIST,
			       flashcache_wait_schedule, TASK_UNINTERRUPTIBLE);
	dmc->next_cache = cache_list_head;
	cache_list_head = dmc;
	clear_bit(FLASHCACHE_UPDATE_LIST, &flashcache_control->synch_flags);
	smp_mb__after_clear_bit();
	wake_up_bit(&flashcache_control->synch_flags, FLASHCACHE_UPDATE_LIST);

	for (i = 0 ; i < dmc->size ; i++) {
		if (dmc->cache[i].cache_state & VALID)
			dmc->cached_blocks++;
		if (dmc->cache[i].cache_state & DIRTY) {
			dmc->cache_sets[i / dmc->assoc].nr_dirty++;
			dmc->nr_dirty++;
		}
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	INIT_WORK(&dmc->delayed_clean, flashcache_clean_all_sets, dmc);
#else
	INIT_DELAYED_WORK(&dmc->delayed_clean, flashcache_clean_all_sets);
#endif

	dmc->nc_pid_list_head = dmc->nc_pid_list_tail = NULL;
	dmc->num_nc_pids = 0;

	return 0;

bad5:
	flashcache_kcached_client_destroy(dmc);
bad4:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	dm_kcopyd_client_destroy(dmc->kcp_client);
	dm_io_client_destroy(dmc->io_client);
#else
	kcopyd_client_destroy(dmc->kcp_client);
#endif
bad3:
	dm_put_device(ti, dmc->cache_dev);
bad2:
	dm_put_device(ti, dmc->disk_dev);
bad1:
	kfree(dmc);
bad:
	return r;
}

static void
flashcache_zero_stats(struct cache_c *dmc)
{
	dmc->reads = 0;
	dmc->writes = 0;
	dmc->read_hits = 0;
	dmc->write_hits = 0;
	dmc->dirty_write_hits = 0;
	dmc->replace = 0;
	dmc->wr_replace = 0;
	dmc->wr_invalidates = 0;
	dmc->rd_invalidates = 0;
	dmc->pending_inval = 0;
	dmc->enqueues = 0;
	dmc->cleanings = 0;
	dmc->noroom = 0;
	dmc->md_write_dirty = 0;
	dmc->md_write_clean = 0;
#ifdef FLASHCACHE_DO_CHECKSUMS
	dmc->checksum_store = 0;
	dmc->checksum_valid = 0;
	dmc->checksum_invalid = 0;
#endif
	dmc->clean_set_calls = dmc->clean_set_less_dirty = 0;
	dmc->clean_set_fails = dmc->clean_set_ios = 0;
	dmc->set_limit_reached = dmc->total_limit_reached = 0;
	dmc->front_merge = dmc->back_merge = 0;
	dmc->nc_pid_drops = dmc->nc_pid_adds = dmc->nc_pid_dels = dmc->nc_expiry = 0;
}

/*
 * Destroy the cache mapping.
 */
void 
flashcache_dtr(struct dm_target *ti)
{
	struct cache_c *dmc = (struct cache_c *) ti->private;
	struct cache_c **nodepp;
	int i;
	int nr_queued = 0;

	flashcache_sync_for_remove(dmc);
	flashcache_md_store(dmc);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	dm_io_put(FLASHCACHE_ASYNC_SIZE); /* Must be done after md_store() */
#endif
	if (!sysctl_flashcache_fast_remove && dmc->nr_dirty > 0)
		DMERR("Could not sync %d blocks to disk, cache still dirty", 
		      dmc->nr_dirty);
	DMINFO("cache jobs %d, pending jobs %d", atomic_read(&nr_cache_jobs), 
	       atomic_read(&nr_pending_jobs));
	for (i = 0 ; i < dmc->size ; i++)
		nr_queued += dmc->cache[i].nr_queued;
	DMINFO("cache queued jobs %d", nr_queued);	
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	kcopyd_client_destroy(dmc->kcp_client);
#else
	dm_kcopyd_client_destroy(dmc->kcp_client);
#endif
	if ((dmc->reads > 0) && (dmc->writes > 0)) {
#ifdef FLASHCACHE_DO_CHECKSUMS
		DMINFO("stats: reads(%lu), writes(%lu), read hits(%lu), write hits(%lu), " \
		       "read hit percent(%ld), replacement(%lu), write invalidates(%lu), " \
		       "read invalidates(%lu), write replacement(%lu), pending enqueues(%lu), " \
		       "pending inval(%lu) cleanings(%lu), " \
		       "checksum invalid(%ld), checksum store(%ld), checksum valid(%ld)" \
		       "front merge(%ld) back merge(%ld)",
		       dmc->reads, dmc->writes, dmc->read_hits, dmc->write_hits,
		       dmc->read_hits*100/dmc->reads,
		       dmc->replace, dmc->wr_invalidates, dmc->rd_invalidates,
		       dmc->wr_replace, dmc->enqueues, dmc->pending_inval, dmc->cleanings,
		       dmc->checksum_store, dmc->checksum_valid, dmc->checksum_invalid,
		       dmc->front_merge, dmc->back_merge);
#else
		DMINFO("stats: reads(%lu), writes(%lu), read hits(%lu), write hits(%lu), " \
		       "read hit percent(%ld), replacement(%lu), write invalidates(%lu), " \
		       "read invalidates(%lu), write replacement(%lu), pending enqueues(%lu), " \
		       "pending inval(%lu) cleanings(%lu)" \
		       "front merge(%ld) back merge(%ld)",
		       dmc->reads, dmc->writes, dmc->read_hits, dmc->write_hits,
		       dmc->read_hits*100/dmc->reads,
		       dmc->replace, dmc->wr_invalidates, dmc->rd_invalidates,
		       dmc->wr_replace, dmc->enqueues, dmc->pending_inval, dmc->cleanings,
		       dmc->front_merge, dmc->back_merge);
#endif

	}
	if (dmc->size > 0) {
		DMINFO("conf: capacity(%luM), associativity(%u), block size(%uK), " \
		       "total blocks(%lu), cached blocks(%lu), cache percent(%ld), dirty blocks(%d)",
		       dmc->size*dmc->block_size>>11, dmc->assoc,
		       dmc->block_size>>(10-SECTOR_SHIFT), 
		       dmc->size, dmc->cached_blocks, 
		       (dmc->cached_blocks*100)/dmc->size, dmc->nr_dirty);
	}
	vfree((void *)dmc->cache);
	vfree((void *)dmc->cache_sets);
	vfree((void *)dmc->md_sectors_buf);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	dm_io_client_destroy(dmc->io_client);
#endif
	flashcache_del_nc_all(dmc);
	VERIFY(dmc->num_nc_pids == 0);
	dm_put_device(ti, dmc->disk_dev);
	dm_put_device(ti, dmc->cache_dev);
	(void)wait_on_bit_lock(&flashcache_control->synch_flags, 
			       FLASHCACHE_UPDATE_LIST,
			       flashcache_wait_schedule, 
			       TASK_UNINTERRUPTIBLE);
	nodepp = &cache_list_head;
	while (*nodepp != NULL) {
		if (*nodepp == dmc) {
			*nodepp = dmc->next_cache;
			break;
		}
		nodepp = &((*nodepp)->next_cache);
	}
	clear_bit(FLASHCACHE_UPDATE_LIST, &flashcache_control->synch_flags);
	smp_mb__after_clear_bit();
	wake_up_bit(&flashcache_control->synch_flags, FLASHCACHE_UPDATE_LIST);
	kfree(dmc);
}

void
flashcache_status_info(struct cache_c *dmc, status_type_t type,
		       char *result, unsigned int maxlen)
{
	int read_hit_pct, write_hit_pct, dirty_write_hit_pct;
	int sz = 0; /* DMEMIT */
	
	if (dmc->reads > 0)
		read_hit_pct = dmc->read_hits * 100 / dmc->reads;
	else
		read_hit_pct = 0;
	if (dmc->writes > 0) {
		write_hit_pct = dmc->write_hits * 100 / dmc->writes;
		dirty_write_hit_pct = dmc->dirty_write_hits * 100 / dmc->writes;		
	} else {
		write_hit_pct = 0;
		dirty_write_hit_pct = 0;
	}
	DMEMIT("stats: \n\treads(%lu), writes(%lu)\n", dmc->reads, dmc->writes);
#ifdef FLASHCACHE_DO_CHECKSUMS
	DMEMIT("\tread hits(%lu), read hit percent(%d)\n"		\
	       "\twrite hits(%lu) write hit percent(%d)\n" 		\
	       "\tdirty write hits(%lu) dirty write hit percent(%d)\n" 	\
	       "\treplacement(%lu), write replacement(%lu)\n"		\
	       "\twrite invalidates(%lu), read invalidates(%lu)\n"	\
	       "\tchecksum store(%ld), checksum valid(%ld), checksum invalid(%ld)\n" \
	       "\tpending enqueues(%lu), pending inval(%lu)\n"		\
	       "\tmetadata dirties(%lu), metadata cleans(%lu)\n" \
	       "\tcleanings(%lu), no room(%lu) front merge(%lu) back merge(%lu)\n" \
	       "\tnc_pid_adds(%lu), nc_pid_dels(%lu), nc_pid_drops(%lu) nc_expiry(%lu)",
	       dmc->read_hits, read_hit_pct, 
	       dmc->write_hits, write_hit_pct,
	       dmc->dirty_write_hits, dirty_write_hit_pct,
	       dmc->replace, dmc->wr_replace, dmc->wr_invalidates, dmc->rd_invalidates,
	       dmc->checksum_store, dmc->checksum_valid, dmc->checksum_invalid,
	       dmc->enqueues, dmc->pending_inval, 
	       dmc->md_write_dirty, dmc->md_write_clean, 
	       dmc->cleanings, dmc->noroom, dmc->front_merge, dmc->back_merge,
	       dmc->nc_pid_adds, dmc->nc_pid_dels, dmc->nc_pid_drops, dmc->nc_expiry);
#else
	DMEMIT("\tread hits(%lu), read hit percent(%d)\n"		\
	       "\twrite hits(%lu) write hit percent(%d)\n" 		\
	       "\tdirty write hits(%lu) dirty write hit percent(%d)\n" 	\
	       "\treplacement(%lu), write replacement(%lu)\n"		\
	       "\twrite invalidates(%lu), read invalidates(%lu)\n"	\
	       "\tpending enqueues(%lu), pending inval(%lu)\n"		\
	       "\tmetadata dirties(%lu), metadata cleans(%lu)\n" \
	       "\tcleanings(%lu), no room(%lu) front merge(%lu) back merge(%lu)\n" \
	       "\tnc_pid_adds(%lu), nc_pid_dels(%lu), nc_pid_drops(%lu) nc_expiry(%lu)",
	       dmc->read_hits, read_hit_pct, 
	       dmc->write_hits, write_hit_pct,
	       dmc->dirty_write_hits, dirty_write_hit_pct,
	       dmc->replace, dmc->wr_replace, dmc->wr_invalidates, dmc->rd_invalidates,
	       dmc->enqueues, dmc->pending_inval, 
	       dmc->md_write_dirty, dmc->md_write_clean, 
	       dmc->cleanings, dmc->noroom, dmc->front_merge, dmc->back_merge,
	       dmc->nc_pid_adds, dmc->nc_pid_dels, dmc->nc_pid_drops, dmc->nc_expiry);
#endif
}

static void
flashcache_status_table(struct cache_c *dmc, status_type_t type,
			     char *result, unsigned int maxlen)
{
	int cache_pct, dirty_pct;
	int i;
	int sz = 0; /* DMEMIT */
	int nr_queued = 0;
	unsigned long flags;

	if (dmc->size > 0) {
		dirty_pct = (dmc->nr_dirty * 100) / dmc->size;
		cache_pct = (dmc->cached_blocks * 100) / dmc->size;
	} else {
		cache_pct = 0;
		dirty_pct = 0;
	}
	DMEMIT("conf:\n"						\
	       "\tssd dev (%s), disk dev (%s)\n"                        \
	       "\tcapacity(%luM), associativity(%u), block size(%uK)\n" \
	       "\ttotal blocks(%lu), cached blocks(%lu), cache percent(%d)\n" \
	       "\tdirty blocks(%d), dirty percent(%d)\n",
	       dmc->cache_devname, dmc->disk_devname,
	       dmc->size*dmc->block_size>>11, dmc->assoc,
	       dmc->block_size>>(10-SECTOR_SHIFT), 
	       dmc->size, dmc->cached_blocks, 
	       cache_pct, dmc->nr_dirty, dirty_pct);
	spin_lock_irqsave(&dmc->cache_spin_lock, flags);
	for (i = 0 ; i < dmc->size ; i++)
		nr_queued += dmc->cache[i].nr_queued;
	DMEMIT("\tnr_queued(%d)\n", nr_queued);
	spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
	DMEMIT("Size Hist: ");
	for (i = 1 ; i <= 32 ; i++) {
		if (size_hist[i] > 0)
			DMEMIT("%d:%llu ", i*512, size_hist[i]);
	}
}

/*
 * Report cache status:
 *  Output cache stats upon request of device status;
 *  Output cache configuration upon request of table status.
 */
int 
flashcache_status(struct dm_target *ti, status_type_t type,
	     char *result, unsigned int maxlen)
{
	struct cache_c *dmc = (struct cache_c *) ti->private;
	
	switch (type) {
	case STATUSTYPE_INFO:
		flashcache_status_info(dmc, type, result, maxlen);
		break;
	case STATUSTYPE_TABLE:
		flashcache_status_table(dmc, type, result, maxlen);
		break;
	}
	return 0;
}

static struct target_type flashcache_target = {
	.name   = "flashcache",
	.version= {1, 0, 1},
	.module = THIS_MODULE,
	.ctr    = flashcache_ctr,
	.dtr    = flashcache_dtr,
	.map    = flashcache_map,
	.status = flashcache_status,
	.ioctl 	= flashcache_ioctl,
};

static void
flashcache_sync_for_remove(struct cache_c *dmc)
{
	do {
		cancel_delayed_work(&dmc->delayed_clean);
		flush_scheduled_work();
		if (!sysctl_flashcache_fast_remove) {
			/* 
			 * Kick off cache cleaning. client_destroy will wait for cleanings
			 * to finish.
			 */
			printk(KERN_ALERT "Cleaning %d blocks please WAIT", dmc->nr_dirty);
			/* Tune up the cleaning parameters to clean very aggressively */
			dmc->max_clean_ios_total = 20;
			dmc->max_clean_ios_set = 10;
			flashcache_sync_all(dmc);
		} else {
			/* Needed to abort any in-progress cleanings, leave blocks DIRTY */
			atomic_set(&dmc->fast_remove_in_prog, 1);
			printk(KERN_ALERT "Fast flashcache remove Skipping cleaning of %d blocks", 
			       dmc->nr_dirty);
		}
		/* 
		 * We've prevented new cleanings from starting (for the fast remove case)
		 * and we will wait for all in progress cleanings to exit.
		 * Wait a few seconds for everything to quiesce before writing out the 
		 * cache metadata.
		 */
		msleep(FLASHCACHE_SYNC_REMOVE_DELAY);
		/* Wait for all the dirty blocks to get written out, and any other IOs */
		wait_event(dmc->destroyq, !atomic_read(&dmc->nr_jobs));
	} while (!sysctl_flashcache_fast_remove && dmc->nr_dirty > 0);
}

static int 
flashcache_notify_reboot(struct notifier_block *this,
			 unsigned long code, void *x)
{
	struct cache_c *dmc;

	(void)wait_on_bit_lock(&flashcache_control->synch_flags, 
			       FLASHCACHE_UPDATE_LIST,
			       flashcache_wait_schedule, 
			       TASK_UNINTERRUPTIBLE);
	for (dmc = cache_list_head ; 
	     dmc != NULL ; 
	     dmc = dmc->next_cache) {
		flashcache_sync_for_remove(dmc);
		flashcache_md_store(dmc);
	}
	clear_bit(FLASHCACHE_UPDATE_LIST, &flashcache_control->synch_flags);
	smp_mb__after_clear_bit();
	wake_up_bit(&flashcache_control->synch_flags, FLASHCACHE_UPDATE_LIST);
	return NOTIFY_DONE;
}

/*
 * The notifiers are registered in descending order of priority and
 * executed in descending order or priority. We should be run before
 * any notifiers of ssd's or other block devices. Typically, devices
 * use a priority of 0.
 * XXX - If in the future we happen to use a md device as the cache
 * block device, we have a problem because md uses a priority of 
 * INT_MAX as well. But we want to run before the md's reboot notifier !
 */
static struct notifier_block flashcache_notifier = {
	.notifier_call	= flashcache_notify_reboot,
	.next		= NULL,
	.priority	= INT_MAX, /* should be > ssd pri's and disk dev pri's */
};

static int 
flashcache_stats_show(struct seq_file *seq, void *v)
{
	struct cache_c *dmc;

	(void)wait_on_bit_lock(&flashcache_control->synch_flags, 
			       FLASHCACHE_UPDATE_LIST,
			       flashcache_wait_schedule, 
			       TASK_UNINTERRUPTIBLE);
	for (dmc = cache_list_head ; 
	     dmc != NULL ; 
	     dmc = dmc->next_cache) {
		int read_hit_pct, write_hit_pct, dirty_write_hit_pct;

		if (dmc->reads > 0)
			read_hit_pct = dmc->read_hits * 100 / dmc->reads;
		else
			read_hit_pct = 0;
		if (dmc->writes > 0) {
			write_hit_pct = dmc->write_hits * 100 / dmc->writes;
			dirty_write_hit_pct = dmc->dirty_write_hits * 100 / dmc->writes;		
		} else {
			write_hit_pct = 0;
			dirty_write_hit_pct = 0;
		}
		seq_printf(seq, "read_hits=%lu read_hit_percent=%d write_hits=%lu write_hit_percent=%d ",
			   dmc->read_hits, read_hit_pct, dmc->write_hits, write_hit_pct);
		seq_printf(seq, "dirty_write_hits=%lu dirty_write_hit_percent=%d ",
			   dmc->dirty_write_hits, dirty_write_hit_pct);
		seq_printf(seq, "replacement=%lu write_replacement=%lu ", 
			   dmc->replace, dmc->wr_replace);
		seq_printf(seq, "write_invalidates=%lu read_invalidates=%lu ", 
			   dmc->wr_invalidates, dmc->rd_invalidates);
		seq_printf(seq, "pending_enqueues=%lu pending_inval=%lu ", 
			   dmc->enqueues, dmc->pending_inval);
		seq_printf(seq, "metadata_dirties=%lu metadata_cleans=%lu ", 
			   dmc->md_write_dirty, dmc->md_write_clean);
		seq_printf(seq, "cleanings=%lu no_room=%lu front_merge=%lu back_merge=%lu ",
			   dmc->cleanings, dmc->noroom, dmc->front_merge, dmc->back_merge);
		seq_printf(seq, "nc_pid_adds=%lu nc_pid_dels=%lu nc_pid_drops=%lu nc_expiry=%lu\n",
			   dmc->nc_pid_adds, dmc->nc_pid_dels, dmc->nc_pid_drops, dmc->nc_expiry);

	}
	clear_bit(FLASHCACHE_UPDATE_LIST, &flashcache_control->synch_flags);
	smp_mb__after_clear_bit();
	wake_up_bit(&flashcache_control->synch_flags, FLASHCACHE_UPDATE_LIST);
	return 0;
}

static int 
flashcache_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, &flashcache_stats_show, NULL);
}

static struct file_operations flashcache_stats_operations = {
	.open		= flashcache_stats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int 
flashcache_errors_show(struct seq_file *seq, void *v)
{
	struct cache_c *dmc;

	(void)wait_on_bit_lock(&flashcache_control->synch_flags, 
			       FLASHCACHE_UPDATE_LIST,
			       flashcache_wait_schedule, 
			       TASK_UNINTERRUPTIBLE);
	for (dmc = cache_list_head ; 
	     dmc != NULL ; 
	     dmc = dmc->next_cache) {
		seq_printf(seq, "disk_read_errors=%d disk_write_errors=%d ",
			   dmc->disk_read_errors, dmc->disk_write_errors);
		seq_printf(seq, "ssd_read_errors=%d ssd_write_errors=%d ",
			   dmc->ssd_read_errors, dmc->ssd_write_errors);
		seq_printf(seq, "memory_alloc_errors=%d\n", dmc->memory_alloc_errors);
		dmc->disk_read_errors = 0;
		dmc->disk_write_errors = 0;
		dmc->ssd_read_errors = 0;
		dmc->ssd_write_errors = 0;
		dmc->memory_alloc_errors = 0;
	}
	clear_bit(FLASHCACHE_UPDATE_LIST, &flashcache_control->synch_flags);
	smp_mb__after_clear_bit();
	wake_up_bit(&flashcache_control->synch_flags, FLASHCACHE_UPDATE_LIST);
	return 0;
}

static int 
flashcache_errors_open(struct inode *inode, struct file *file)
{
	return single_open(file, &flashcache_errors_show, NULL);
}

static struct file_operations flashcache_errors_operations = {
	.open		= flashcache_errors_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/*
 * Initiate a cache target.
 */
int __init 
flashcache_init(void)
{
	int r;

	r = flashcache_jobs_init();
	if (r)
		return r;
	atomic_set(&nr_cache_jobs, 0);
	atomic_set(&nr_pending_jobs, 0);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	INIT_WORK(&_kcached_wq, do_work, NULL);
#else
	INIT_WORK(&_kcached_wq, do_work);
#endif
	for (r = 0 ; r < 33 ; r++)
		size_hist[r] = 0;
	r = dm_register_target(&flashcache_target);
	if (r < 0) {
		DMERR("cache: register failed %d", r);
	}
#ifdef CONFIG_PROC_FS
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	flashcache_table_header = 
		register_sysctl_table(flashcache_root_table, 1);
#else
	flashcache_table_header = 
		register_sysctl_table(flashcache_root_table);
#endif
	{
		struct proc_dir_entry *entry;
		
		entry = create_proc_entry("flashcache_stats", 0, NULL);
		if (entry)
			entry->proc_fops =  &flashcache_stats_operations;
		entry = create_proc_entry("flashcache_errors", 0, NULL);
		if (entry)
			entry->proc_fops =  &flashcache_errors_operations;		
	}
#endif
	flashcache_control = (struct flashcache_control_s *)
		kmalloc(sizeof(struct flashcache_control_s *), GFP_KERNEL);
	flashcache_control->synch_flags = 0;
	register_reboot_notifier(&flashcache_notifier);
	return r;
}

/*
 * Destroy a cache target.
 */
void 
flashcache_exit(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	int r = dm_unregister_target(&flashcache_target);

	if (r < 0)
		DMERR("cache: unregister failed %d", r);
#else
	dm_unregister_target(&flashcache_target);
#endif
	unregister_reboot_notifier(&flashcache_notifier);
	flashcache_jobs_exit();
#ifdef CONFIG_PROC_FS
	unregister_sysctl_table(flashcache_table_header);
	remove_proc_entry("flashcache_stats", NULL);
	remove_proc_entry("flashcache_errors", NULL);
#endif
	kfree(flashcache_control);
}

module_init(flashcache_init);
module_exit(flashcache_exit);

EXPORT_SYMBOL(flashcache_md_load);
EXPORT_SYMBOL(flashcache_md_create);
EXPORT_SYMBOL(flashcache_md_store);

MODULE_DESCRIPTION(DM_NAME " Facebook flash cache target");
MODULE_AUTHOR("Mohan - based on code by Ming");
MODULE_LICENSE("GPL");
