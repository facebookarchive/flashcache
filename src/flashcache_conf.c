/****************************************************************************
 *  flashcache_conf.c
 *  FlashCache: Device mapper target for block-level disk caching
 *
 *  Copyright 2010 Facebook, Inc.
 *  Author: Mohan Srinivasan (mohan@fb.com)
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
#include <linux/vmalloc.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#include "dm.h"
#include "dm-io.h"
#include "dm-bio-list.h"
#include "kcopyd.h"
#else
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,27)
#include "dm.h"
#endif
#include <linux/device-mapper.h>
#include <linux/bio.h>
#include <linux/dm-kcopyd.h>
#endif

#include "flashcache.h"
#include "flashcache_ioctl.h"

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

struct flashcache_control_s {
	unsigned long synch_flags;
};

struct flashcache_control_s *flashcache_control;

/* Bit offsets for wait_on_bit_lock() */
#define FLASHCACHE_UPDATE_LIST		0

static int flashcache_notify_reboot(struct notifier_block *this,
				    unsigned long code, void *x);
static void flashcache_sync_for_remove(struct cache_c *dmc);

extern char *flashcache_sw_version;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
static int
flashcache_wait_schedule(void *unused)
{
	schedule();
	return 0;
}
#endif

static int 
flashcache_jobs_init(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
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
	init_waitqueue_head(&dmc->destroyq);
	atomic_set(&dmc->nr_jobs, 0);
	atomic_set(&dmc->remove_in_prog, 0);
	return 0;
}

/*
 * Write out the metadata one sector at a time.
 * Then dump out the superblock.
 */
static int 
flashcache_writeback_md_store(struct cache_c *dmc)
{
	struct flash_cacheblock *meta_data_cacheblock, *next_ptr;
	struct flash_superblock *header;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	struct io_region where;
#else
	struct dm_io_region where;
#endif
	int i, j;
	int num_valid = 0, num_dirty = 0;
	int error;
	int write_errors = 0;
	int sectors_written = 0, sectors_expected = 0; /* debug */
	int slots_written = 0; /* How many cache slots did we fill in this MD io block ? */

	meta_data_cacheblock = (struct flash_cacheblock *)vmalloc(METADATA_IO_BLOCKSIZE);
	if (!meta_data_cacheblock) {
		DMERR("flashcache_writeback_md_store: Unable to allocate memory");
		DMERR("flashcache_writeback_md_store: Could not write out cache metadata !");
		return 1;
	}	

	where.bdev = dmc->cache_dev->bdev;
	where.sector = MD_SECTORS_PER_BLOCK(dmc);
	slots_written = 0;
	next_ptr = meta_data_cacheblock;
	j = MD_SLOTS_PER_BLOCK(dmc);
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
		slots_written++;
		j--;
		if (j == 0) {
			/* 
			 * Filled the block, write and goto the next metadata block.
			 */
			if (slots_written == MD_SLOTS_PER_BLOCK(dmc) * METADATA_IO_NUM_BLOCKS(dmc)) {
				/*
				 * Wrote out an entire metadata IO block, write the block to the ssd.
				 */
				where.count = (slots_written / MD_SLOTS_PER_BLOCK(dmc)) * 
					MD_SECTORS_PER_BLOCK(dmc);
				slots_written = 0;
				sectors_written += where.count;	/* debug */
				error = flashcache_dm_io_sync_vm(dmc, &where, WRITE, meta_data_cacheblock);
				if (error) {
					write_errors++;
					DMERR("flashcache_writeback_md_store: Could not write out cache metadata block %lu error %d !",
					      where.sector, error);
				}
				where.sector += where.count;	/* Advance offset */
			}
			/* Move next slot pointer into next block */
			next_ptr = (struct flash_cacheblock *)
				((caddr_t)meta_data_cacheblock + ((slots_written / MD_SLOTS_PER_BLOCK(dmc)) * MD_BLOCK_BYTES(dmc)));
			j = MD_SLOTS_PER_BLOCK(dmc);
		}
	}
	if (next_ptr != meta_data_cacheblock) {
		/* Write the remaining last blocks out */
		VERIFY(slots_written > 0);
		where.count = (slots_written / MD_SLOTS_PER_BLOCK(dmc)) * MD_SECTORS_PER_BLOCK(dmc);
		if (slots_written % MD_SLOTS_PER_BLOCK(dmc))
			where.count += MD_SECTORS_PER_BLOCK(dmc);
		sectors_written += where.count;
		error = flashcache_dm_io_sync_vm(dmc, &where, WRITE, meta_data_cacheblock);
		if (error) {
			write_errors++;
				DMERR("flashcache_writeback_md_store: Could not write out cache metadata block %lu error %d !",
				      where.sector, error);
		}
	}
	/* Debug Tests */
	sectors_expected = (dmc->size / MD_SLOTS_PER_BLOCK(dmc)) * MD_SECTORS_PER_BLOCK(dmc);
	if (dmc->size % MD_SLOTS_PER_BLOCK(dmc))
		sectors_expected += MD_SECTORS_PER_BLOCK(dmc);
	if (sectors_expected != sectors_written) {
		printk("flashcache_writeback_md_store" "Sector Mismatch ! sectors_expected=%d, sectors_written=%d\n",
		       sectors_expected, sectors_written);
		panic("flashcache_writeback_md_store: sector mismatch\n");
	}

	vfree((void *)meta_data_cacheblock);

	header = (struct flash_superblock *)vmalloc(MD_BLOCK_BYTES(dmc));
	if (!header) {
		DMERR("flashcache_writeback_md_store: Unable to allocate memory");
		DMERR("flashcache_writeback_md_store: Could not write out cache metadata !");
		return 1;
	}	
	memset(header, 0, MD_BLOCK_BYTES(dmc));
	
	/* Write the header out last */
	if (write_errors == 0) {
		if (num_dirty == 0)
			header->cache_sb_state = CACHE_MD_STATE_CLEAN;
		else
			header->cache_sb_state = CACHE_MD_STATE_FASTCLEAN;			
	} else
		header->cache_sb_state = CACHE_MD_STATE_UNSTABLE;
	header->block_size = dmc->block_size;
	header->md_block_size = dmc->md_block_size;
	header->size = dmc->size;
	header->assoc = dmc->assoc;
	header->disk_assoc = dmc->disk_assoc;
	strncpy(header->disk_devname, dmc->disk_devname, DEV_PATHLEN);
	strncpy(header->cache_devname, dmc->dm_vdevname, DEV_PATHLEN);
	header->cache_devsize = to_sector(dmc->cache_dev->bdev->bd_inode->i_size);
	header->disk_devsize = to_sector(dmc->disk_dev->bdev->bd_inode->i_size);
	header->cache_version = dmc->on_ssd_version;
	header->write_only_cache = dmc->write_only_cache;
	
	DPRINTK("Store metadata to disk: block size(%u), md block size(%u), cache size(%llu)" \
	        "associativity(%u)",
	        header->block_size, header->md_block_size, header->size,
	        header->assoc);

	where.sector = 0;
	where.count = dmc->md_block_size;
	error = flashcache_dm_io_sync_vm(dmc, &where, WRITE, header);
	if (error) {
		write_errors++;
		DMERR("flashcache_writeback_md_store: Could not write out cache metadata superblock %lu error %d !",
		      where.sector, error);
	}

	vfree((void *)header);

	if (write_errors == 0)
		DMINFO("Cache metadata saved to disk");
	else {
		DMINFO("CRITICAL : There were %d errors in saving cache metadata saved to disk", 
		       write_errors);
		if (num_dirty)
			DMINFO("CRITICAL : You have likely lost %d dirty blocks", num_dirty);
	}

	DMINFO("flashcache_writeback_md_store: valid blocks = %d dirty blocks = %d md_sectors = %d\n", 
	       num_valid, num_dirty, dmc->md_blocks * MD_SECTORS_PER_BLOCK(dmc));

	return 0;
}

static int 
flashcache_writethrough_create(struct cache_c *dmc)
{
	sector_t cache_size, dev_size;
	sector_t order;
	int i;
	
	/* 
	 * Convert size (in sectors) to blocks.
	 * Then round size (in blocks now) down to a multiple of associativity 
	 */
	dmc->size /= dmc->block_size;
	dmc->size = (dmc->size / dmc->assoc) * dmc->assoc;

	/* Check cache size against device size */
	dev_size = to_sector(dmc->cache_dev->bdev->bd_inode->i_size);
	cache_size = dmc->size * dmc->block_size;
	if (cache_size > dev_size) {
		DMERR("Requested cache size exeeds the cache device's capacity" \
		      "(%lu>%lu)",
  		      cache_size, dev_size);
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
		DMERR("flashcache_writethrough_create: Unable to allocate cache md");
		return 1;
	}
	memset(dmc->cache, 0, order);
	/* Initialize the cache structs */
	for (i = 0; i < dmc->size ; i++) {
		dmc->cache[i].dbn = 0;
#ifdef FLASHCACHE_DO_CHECKSUMS
		dmc->cache[i].checksum = 0;
#endif
		dmc->cache[i].cache_state = INVALID;
		dmc->cache[i].lru_state = 0;
		dmc->cache[i].nr_queued = 0;
	}
	dmc->md_blocks = 0;
	return 0;
}

static int 
flashcache_writeback_create(struct cache_c *dmc, int force)
{
	struct flash_cacheblock *meta_data_cacheblock, *next_ptr;
	struct flash_superblock *header;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	struct io_region where;
#else
	struct dm_io_region where;
#endif
	int i, j, error;
	sector_t cache_size, dev_size;
	sector_t order;
	int sectors_written = 0, sectors_expected = 0; /* debug */
	int slots_written = 0; /* How many cache slots did we fill in this MD io block ? */
	
	header = (struct flash_superblock *)vmalloc(MD_BLOCK_BYTES(dmc));
	if (!header) {
		DMERR("flashcache_writeback_create: Unable to allocate sector");
		return 1;
	}
	where.bdev = dmc->cache_dev->bdev;
	where.sector = 0;
	where.count = dmc->md_block_size;
	error = flashcache_dm_io_sync_vm(dmc, &where, READ, header);
	if (error) {
		vfree((void *)header);
		DMERR("flashcache_writeback_create: Could not read cache superblock %lu error %d !",
		      where.sector, error);
		return 1;
	}
	if (!force &&
	    ((header->cache_sb_state == CACHE_MD_STATE_DIRTY) ||
	     (header->cache_sb_state == CACHE_MD_STATE_CLEAN) ||
	     (header->cache_sb_state == CACHE_MD_STATE_FASTCLEAN))) {
		vfree((void *)header);
		DMERR("flashcache_writeback_create: Existing Cache Detected, use force to re-create");
		return 1;
	}
	/* Compute the size of the metadata, including header. 
	   Note dmc->size is in raw sectors */
	dmc->md_blocks = INDEX_TO_MD_BLOCK(dmc, dmc->size / dmc->block_size) + 1 + 1;
	dmc->size -= dmc->md_blocks * MD_SECTORS_PER_BLOCK(dmc);	/* total sectors available for cache */
	dmc->size /= dmc->block_size;
	dmc->size = (dmc->size / dmc->assoc) * dmc->assoc;	
	/* Recompute since dmc->size was possibly trunc'ed down */
	dmc->md_blocks = INDEX_TO_MD_BLOCK(dmc, dmc->size) + 1 + 1;
	DMINFO("flashcache_writeback_create: md_blocks = %d, md_sectors = %d\n", 
	       dmc->md_blocks, dmc->md_blocks * MD_SECTORS_PER_BLOCK(dmc));
	dev_size = to_sector(dmc->cache_dev->bdev->bd_inode->i_size);
	cache_size = dmc->md_blocks * MD_SECTORS_PER_BLOCK(dmc) + (dmc->size * dmc->block_size);
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
		DMERR("flashcache_writeback_create: Unable to allocate cache md");
		return 1;
	}
	memset(dmc->cache, 0, order);
	/* Initialize the cache structs */
	for (i = 0; i < dmc->size ; i++) {
		dmc->cache[i].dbn = 0;
#ifdef FLASHCACHE_DO_CHECKSUMS
		dmc->cache[i].checksum = 0;
#endif
		dmc->cache[i].cache_state = INVALID;
		dmc->cache[i].lru_state = 0;
		dmc->cache[i].nr_queued = 0;
	}
	meta_data_cacheblock = (struct flash_cacheblock *)vmalloc(METADATA_IO_BLOCKSIZE);
	if (!meta_data_cacheblock) {
		DMERR("flashcache_writeback_create: Unable to allocate memory");
		DMERR("flashcache_writeback_create: Could not write out cache metadata !");
		return 1;
	}	
	where.sector = MD_SECTORS_PER_BLOCK(dmc);
	slots_written = 0;
	next_ptr = meta_data_cacheblock;
	j = MD_SLOTS_PER_BLOCK(dmc);
	for (i = 0 ; i < dmc->size ; i++) {
		next_ptr->dbn = dmc->cache[i].dbn;
#ifdef FLASHCACHE_DO_CHECKSUMS
		next_ptr->checksum = dmc->cache[i].checksum;
#endif
		next_ptr->cache_state = dmc->cache[i].cache_state & 
			(INVALID | VALID | DIRTY);
		next_ptr++;
		slots_written++;
		j--;
		if (j == 0) {
			/* 
			 * Filled the block, write and goto the next metadata block.
			 */
			if (slots_written == MD_SLOTS_PER_BLOCK(dmc) * METADATA_IO_NUM_BLOCKS(dmc)) {
				/*
				 * Wrote out an entire metadata IO block, write the block to the ssd.
				 */
				where.count = (slots_written / MD_SLOTS_PER_BLOCK(dmc)) * MD_SECTORS_PER_BLOCK(dmc);
				slots_written = 0;
				sectors_written += where.count;	/* debug */
				error = flashcache_dm_io_sync_vm(dmc, &where, WRITE, 
								 meta_data_cacheblock);
				if (error) {
					vfree((void *)header);
					vfree((void *)meta_data_cacheblock);
					vfree(dmc->cache);
					DMERR("flashcache_writeback_create: Could not write cache metadata block %lu error %d !",
					      where.sector, error);
					return 1;
				}
				where.sector += where.count;	/* Advance offset */
			}
			/* Move next slot pointer into next metadata block */
			next_ptr = (struct flash_cacheblock *)
				((caddr_t)meta_data_cacheblock + ((slots_written / MD_SLOTS_PER_BLOCK(dmc)) * MD_BLOCK_BYTES(dmc)));
			j = MD_SLOTS_PER_BLOCK(dmc);
		}
	}
	if (next_ptr != meta_data_cacheblock) {
		/* Write the remaining last blocks out */
		VERIFY(slots_written > 0);
		where.count = (slots_written / MD_SLOTS_PER_BLOCK(dmc)) * MD_SECTORS_PER_BLOCK(dmc);
		if (slots_written % MD_SLOTS_PER_BLOCK(dmc))
			where.count += MD_SECTORS_PER_BLOCK(dmc);
		sectors_written += where.count;
		error = flashcache_dm_io_sync_vm(dmc, &where, WRITE, meta_data_cacheblock);
		if (error) {
			vfree((void *)header);
			vfree((void *)meta_data_cacheblock);
			vfree(dmc->cache);
			DMERR("flashcache_writeback_create: Could not write cache metadata block %lu error %d !",
			      where.sector, error);
			return 1;		
		}
	}
	/* Debug Tests */
	sectors_expected = (dmc->size / MD_SLOTS_PER_BLOCK(dmc)) * MD_SECTORS_PER_BLOCK(dmc);
	if (dmc->size % MD_SLOTS_PER_BLOCK(dmc))
		sectors_expected += MD_SECTORS_PER_BLOCK(dmc);
	if (sectors_expected != sectors_written) {
		printk("flashcache_writeback_create" "Sector Mismatch ! sectors_expected=%d, sectors_written=%d\n",
		       sectors_expected, sectors_written);
		panic("flashcache_writeback_create: sector mismatch\n");
	}
	vfree((void *)meta_data_cacheblock);
	/* Write the header */
	header->cache_sb_state = CACHE_MD_STATE_DIRTY;
	header->block_size = dmc->block_size;
	header->md_block_size = dmc->md_block_size;
	header->size = dmc->size;
	header->assoc = dmc->assoc;
	header->disk_assoc = dmc->disk_assoc;
	strncpy(header->disk_devname, dmc->disk_devname, DEV_PATHLEN);
	strncpy(header->cache_devname, dmc->dm_vdevname, DEV_PATHLEN);
	header->cache_devsize = to_sector(dmc->cache_dev->bdev->bd_inode->i_size);
	header->disk_devsize = to_sector(dmc->disk_dev->bdev->bd_inode->i_size);
	dmc->on_ssd_version = header->cache_version = FLASHCACHE_VERSION;
	header->write_only_cache = dmc->write_only_cache;
	where.sector = 0;
	where.count = dmc->md_block_size;
	
	printk("flashcache-dbg: cachedev check - %s %s", header->cache_devname,
				dmc->dm_vdevname);
	
	error = flashcache_dm_io_sync_vm(dmc, &where, WRITE, header);
	if (error) {
		vfree((void *)header);
		vfree(dmc->cache);
		DMERR("flashcache_writeback_create: Could not write cache superblock %lu error %d !",
		      where.sector, error);
		return 1;		
	}
	vfree((void *)header);
	return 0;
}

static int 
flashcache_writeback_load(struct cache_c *dmc)
{
	struct flash_cacheblock *meta_data_cacheblock, *next_ptr;
	struct flash_superblock *header;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	struct io_region where;
#else
	struct dm_io_region where;
#endif
	int i, j;
	u_int64_t size, slots_read;
	int clean_shutdown;
	int dirty_loaded = 0;
	sector_t order, data_size;
	int num_valid = 0;
	int error;
	int sectors_read = 0, sectors_expected = 0;	/* Debug */

	/* 
	 * We don't know what the preferred block size is, just read off 
	 * the default md blocksize.
	 */
	header = (struct flash_superblock *)vmalloc(DEFAULT_MD_BLOCK_SIZE_BYTES);
	if (!header) {
		DMERR("flashcache_writeback_load: Unable to allocate memory");
		return 1;
	}
	where.bdev = dmc->cache_dev->bdev;
	where.sector = 0;
	where.count = DEFAULT_MD_BLOCK_SIZE;
	error = flashcache_dm_io_sync_vm(dmc, &where, READ, header);
	if (error) {
		vfree((void *)header);
		DMERR("flashcache_writeback_load: Could not read cache superblock %lu error %d!",
		      where.sector, error);
		return 1;
	}

	if (header->cache_version == 1) {
		/* Backwards compatibility, md was 512 bytes always in V1.0 */
		header->md_block_size = 1;
	} else if (header->cache_version > FLASHCACHE_VERSION) {
		vfree((void *)header);
		DMERR("flashcache_writeback_load: Unknown version %d found in superblock!", header->cache_version);
		return 1;
	}
	dmc->disk_assoc = header->disk_assoc;
	dmc->write_only_cache = header->write_only_cache;
	
	if (header->cache_version < 3)
		/* Disk Assoc was introduced in On SSD version 3 */
		dmc->disk_assoc = 0;
	if (dmc->disk_assoc != 0)
		dmc->disk_assoc_shift = ffs(dmc->disk_assoc) - 1;

	if (header->cache_version < 4)
		/* write_only_cache was introduced in On SSD version 4 */
		dmc->write_only_cache = 0;

	dmc->on_ssd_version = header->cache_version;
		
	DPRINTK("Loaded cache conf: version(%d), block size(%u), md block size(%u), cache size(%llu), " \
	        "associativity(%u)",
	        header->cache_version, header->block_size, header->md_block_size, header->size,
	        header->assoc);
	if (!((header->cache_sb_state == CACHE_MD_STATE_DIRTY) ||
	      (header->cache_sb_state == CACHE_MD_STATE_CLEAN) ||
	      (header->cache_sb_state == CACHE_MD_STATE_FASTCLEAN))) {
		vfree((void *)header);
		DMERR("flashcache_writeback_load: Corrupt Cache Superblock");
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
	dmc->md_block_size = header->md_block_size;
	dmc->block_shift = ffs(dmc->block_size) - 1;
	dmc->block_mask = dmc->block_size - 1;
	dmc->size = header->size;
	dmc->assoc = header->assoc;
	dmc->assoc_shift = ffs(dmc->assoc) - 1;
	dmc->md_blocks = INDEX_TO_MD_BLOCK(dmc, dmc->size) + 1 + 1;
	DMINFO("flashcache_writeback_load: md_blocks = %d, md_sectors = %d, md_block_size = %d\n", 
	       dmc->md_blocks, dmc->md_blocks * MD_SECTORS_PER_BLOCK(dmc), dmc->md_block_size);
	data_size = dmc->size * dmc->block_size;
	order = dmc->size * sizeof(struct cacheblock);
	DMINFO("Allocate %luKB (%ldB per) mem for %lu-entry cache" \
	       "(capacity:%luMB, associativity:%u, block size:%u " \
	       "sectors(%uKB))",
	       order >> 10, sizeof(struct cacheblock), dmc->size,
	       (dmc->md_blocks * MD_SECTORS_PER_BLOCK(dmc) + data_size) >> (20-SECTOR_SHIFT), 
	       dmc->assoc, dmc->block_size,
	       dmc->block_size >> (10-SECTOR_SHIFT));
	dmc->cache = (struct cacheblock *)vmalloc(order);
	if (!dmc->cache) {
		DMERR("load_metadata: Unable to allocate memory");
		vfree((void *)header);
		return 1;
	}
	memset(dmc->cache, 0, order);
	/* Read the metadata in large blocks and populate incore state */
	meta_data_cacheblock = (struct flash_cacheblock *)vmalloc(METADATA_IO_BLOCKSIZE);
	if (!meta_data_cacheblock) {
		vfree((void *)header);
		vfree(dmc->cache);
		DMERR("flashcache_writeback_load: Unable to allocate memory");
		return 1;
	}
	where.sector = MD_SECTORS_PER_BLOCK(dmc);
	size = dmc->size;
	i = 0;
	while (size > 0) {
		slots_read = min(size, (u_int64_t)(MD_SLOTS_PER_BLOCK(dmc) * METADATA_IO_NUM_BLOCKS(dmc)));
		if (slots_read % MD_SLOTS_PER_BLOCK(dmc))
			where.count = (1 + (slots_read / MD_SLOTS_PER_BLOCK(dmc))) * MD_SECTORS_PER_BLOCK(dmc);
		else
			where.count = (slots_read / MD_SLOTS_PER_BLOCK(dmc)) * MD_SECTORS_PER_BLOCK(dmc);
		sectors_read += where.count;	/* Debug */
		error = flashcache_dm_io_sync_vm(dmc, &where, READ, meta_data_cacheblock);
		if (error) {
			vfree((void *)header);
			vfree(dmc->cache);
			vfree((void *)meta_data_cacheblock);
			DMERR("flashcache_writeback_load: Could not read cache metadata block %lu error %d !",
			      where.sector, error);
			return 1;
		}
		where.sector += where.count;
		next_ptr = meta_data_cacheblock;
		for (j = 0 ; j < slots_read ; j++) {
			/*
			 * XXX - Now that we force each on-ssd metadata cache slot to be a ^2, where
			 * we are guaranteed that the slots will exactly fit within a sector (and 
			 * a metadata block), we can simplify this logic. We don't need this next test.
			 */
			if ((j % MD_SLOTS_PER_BLOCK(dmc)) == 0) {
				/* Move onto next block */
				next_ptr = (struct flash_cacheblock *)
					((caddr_t)meta_data_cacheblock + MD_BLOCK_BYTES(dmc) * (j / MD_SLOTS_PER_BLOCK(dmc)));
			}
			dmc->cache[i].nr_queued = 0;
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
						vfree((void *)meta_data_cacheblock);
						DMERR("flashcache_writeback_load: Could not read cache metadata block %lu error %d !",
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
	/* Debug Tests */
	sectors_expected = (dmc->size / MD_SLOTS_PER_BLOCK(dmc)) * MD_SECTORS_PER_BLOCK(dmc);
	if (dmc->size % MD_SLOTS_PER_BLOCK(dmc))
		sectors_expected += MD_SECTORS_PER_BLOCK(dmc);
	if (sectors_expected != sectors_read) {
		printk("flashcache_writeback_load" "Sector Mismatch ! sectors_expected=%d, sectors_read=%d\n",
		       sectors_expected, sectors_read);
		panic("flashcache_writeback_load: sector mismatch\n");
	}
	vfree((void *)meta_data_cacheblock);
	/*
	 * For writing the superblock out, use the preferred blocksize that 
	 * we read from the superblock above.
	 */
	if (DEFAULT_MD_BLOCK_SIZE != dmc->md_block_size) {
		vfree((void *)header);
		header = (struct flash_superblock *)vmalloc(MD_BLOCK_BYTES(dmc));
		if (!header) {
			DMERR("flashcache_writeback_load: Unable to allocate memory");
			return 1;
		}
	}	
	/* Before we finish loading, we need to dirty the superblock and 
	   write it out */
	header->size = dmc->size;
	header->block_size = dmc->block_size;
	header->md_block_size = dmc->md_block_size;
	header->assoc = dmc->assoc;
	header->disk_assoc = dmc->disk_assoc;
	header->cache_sb_state = CACHE_MD_STATE_DIRTY;
	strncpy(header->disk_devname, dmc->disk_devname, DEV_PATHLEN);
	strncpy(header->cache_devname, dmc->dm_vdevname, DEV_PATHLEN);
	header->cache_devsize = to_sector(dmc->cache_dev->bdev->bd_inode->i_size);
	header->disk_devsize = to_sector(dmc->disk_dev->bdev->bd_inode->i_size);
	header->cache_version = dmc->on_ssd_version;
	where.sector = 0;
	where.count = dmc->md_block_size;
	error = flashcache_dm_io_sync_vm(dmc, &where, WRITE, header);
	if (error) {
		vfree((void *)header);
		vfree(dmc->cache);
		DMERR("flashcache_writeback_load: Could not write cache superblock %lu error %d !",
		      where.sector, error);
		return 1;		
	}
	vfree((void *)header);
	DMINFO("flashcache_writeback_load: Cache metadata loaded from disk with %d valid %d DIRTY blocks", 
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
	
	for (i = 0 ; i < dmc->num_sets ; i++)
		flashcache_clean_set(dmc, i, 0);
}

static int inline
flashcache_get_dev(struct dm_target *ti, char *pth, struct dm_dev **dmd,
		   char *dmc_dname, sector_t tilen)
{
	int rc;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
	rc = dm_get_device(ti, pth,
			   dm_table_get_mode(ti->table), dmd);
#else
#if defined(RHEL_MAJOR) && RHEL_MAJOR == 6
	rc = dm_get_device(ti, pth,
			   dm_table_get_mode(ti->table), dmd);
#else 
	rc = dm_get_device(ti, pth, 0, tilen,
			   dm_table_get_mode(ti->table), dmd);
#endif
#endif
	if (!rc)
		strncpy(dmc_dname, pth, DEV_PATHLEN);
	return rc;
}

/*
 * Construct a cache mapping.
 *  arg[0]: path to source device
 *  arg[1]: path to cache device
 *  arg[2]: md virtual device name
 *  arg[3]: cache mode (from flashcache.h)
 *  arg[4]: cache persistence (if set, cache conf is loaded from disk)
 * Cache configuration parameters (if not set, default values are used.
 *  arg[5]: cache block size (in sectors)
 *  arg[6]: cache size (in blocks)
 *  arg[7]: cache associativity
 *  arg[8]: md block size (in sectors)
 */
int 
flashcache_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct cache_c *dmc;
	sector_t i, order;
	int r = -EINVAL;
	int persistence = 0;
	
	if (argc < 3) {
		ti->error = "flashcache: Need at least 3 arguments";
		goto bad;
	}

	dmc = kzalloc(sizeof(*dmc), GFP_KERNEL);
	if (dmc == NULL) {
		ti->error = "flashcache: Failed to allocate cache context";
		r = ENOMEM;
		goto bad;
	}

	dmc->tgt = ti;
	if ((r = flashcache_get_dev(ti, argv[0], &dmc->disk_dev, 
				    dmc->disk_devname, ti->len))) {
		if (r == -EBUSY)
			ti->error = "flashcache: Disk device is busy, cannot create cache";
		else
			ti->error = "flashcache: Disk device lookup failed";
		goto bad1;
	}
	if ((r = flashcache_get_dev(ti, argv[1], &dmc->cache_dev,
				    dmc->cache_devname, 0))) {
		if (r == -EBUSY)
			ti->error = "flashcache: Cache device is busy, cannot create cache";
		else
			ti->error = "flashcache: Cache device lookup failed";
		goto bad2;
	}

	if (sscanf(argv[2], "%s", (char *)&dmc->dm_vdevname) != 1) {
		ti->error = "flashcache: Virtual device name lookup failed";
		goto bad3;
	}

	r = flashcache_kcached_init(dmc);
	if (r) {
		ti->error = "Failed to initialize kcached";
		goto bad3;
	}

	if (sscanf(argv[3], "%u", &dmc->cache_mode) != 1) {
		ti->error = "flashcache: sscanf failed, invalid cache mode";
		r = -EINVAL;
		goto bad3;
	}
	if (dmc->cache_mode < FLASHCACHE_WRITE_BACK || 
	    dmc->cache_mode > FLASHCACHE_WRITE_AROUND) {
		DMERR("cache_mode = %d", dmc->cache_mode);
		ti->error = "flashcache: Invalid cache mode";
		r = -EINVAL;
		goto bad3;
	}

	/* 
	 * XXX - Persistence is totally ignored for write through and write around.
	 * Maybe this should really be moved to the end of the param list ?
	 */
	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) {
		if (argc >= 5) {
			if (sscanf(argv[4], "%u", &persistence) != 1) {
				ti->error = "flashcache: sscanf failed, invalid cache persistence";
				r = -EINVAL;
				goto bad3;
			}
			if (persistence < CACHE_RELOAD || persistence > CACHE_FORCECREATE) {
				DMERR("persistence = %d", persistence);
				ti->error = "flashcache: Invalid cache persistence";
				r = -EINVAL;
				goto bad3;
			}			
		}
		if (persistence == CACHE_RELOAD) {
			if (flashcache_writeback_load(dmc)) {
				ti->error = "flashcache: Cache reload failed";
				r = -EINVAL;
				goto bad3;
			}
			goto init; /* Skip reading cache parameters from command line */
		}
	} else
		persistence = CACHE_CREATE;

	if (argc >= 6) {
		if (sscanf(argv[5], "%u", &dmc->block_size) != 1) {
			ti->error = "flashcache: Invalid block size";
			r = -EINVAL;
			goto bad3;
		}
		if (!dmc->block_size || (dmc->block_size & (dmc->block_size - 1))) {
			ti->error = "flashcache: Invalid block size";
			r = -EINVAL;
			goto bad3;
		}
	}
	
	if (!dmc->block_size)
		dmc->block_size = DEFAULT_BLOCK_SIZE;
	dmc->block_shift = ffs(dmc->block_size) - 1;
	dmc->block_mask = dmc->block_size - 1;

	/* dmc->size is specified in sectors here, and converted to blocks later */
	if (argc >= 7) {
		if (sscanf(argv[6], "%lu", &dmc->size) != 1) {
			ti->error = "flashcache: Invalid cache size";
			r = -EINVAL;
			goto bad3;
		}
	}
	
	if (!dmc->size)
		dmc->size = to_sector(dmc->cache_dev->bdev->bd_inode->i_size);

	if (argc >= 8) {
		if (sscanf(argv[7], "%u", &dmc->assoc) != 1) {
			ti->error = "flashcache: Invalid cache associativity";
			r = -EINVAL;
			goto bad3;
		}
		if (!dmc->assoc || (dmc->assoc & (dmc->assoc - 1)) ||
		    dmc->assoc > FLASHCACHE_MAX_ASSOC ||
		    dmc->assoc < FLASHCACHE_MIN_ASSOC ||
		    dmc->size < dmc->assoc) {
			ti->error = "flashcache: Invalid cache associativity";
			r = -EINVAL;
			goto bad3;
		}
	}
	if (!dmc->assoc)
		dmc->assoc = DEFAULT_CACHE_ASSOC;
	dmc->assoc_shift = ffs(dmc->assoc) - 1;

	if (argc >= 9) {
		if (sscanf(argv[8], "%u", &dmc->disk_assoc) != 1) {
			ti->error = "flashcache: Invalid disk associativity";
			r = -EINVAL;
			goto bad3;
		}
		/* disk_assoc of 0 is permitted value */
		if ((dmc->disk_assoc > 0) &&
		    ((!dmc->disk_assoc || (dmc->disk_assoc & (dmc->disk_assoc - 1)) ||
		      dmc->disk_assoc > FLASHCACHE_MAX_DISK_ASSOC ||
		      dmc->disk_assoc < FLASHCACHE_MIN_DISK_ASSOC ||
		      dmc->size < dmc->disk_assoc ||
		      (dmc->assoc * dmc->block_shift) < dmc->disk_assoc))) {
			printk(KERN_ERR "Invalid Disk Assoc assoc %d disk_assoc %d size %ld\n",
			       dmc->assoc, dmc->disk_assoc, dmc->size);
			ti->error = "flashcache: Invalid disk associativity";
			r = -EINVAL;
			goto bad3;
		}
	}
	if (dmc->disk_assoc != 0)
		dmc->disk_assoc_shift = ffs(dmc->disk_assoc) - 1;

	if (argc >= 10) {
		if (sscanf(argv[9], "%u", &dmc->write_only_cache) != 1) {
			ti->error = "flashcache: Invalid Write Cache setting";
			r = -EINVAL;
			goto bad3;
		}
		if ((dmc->write_only_cache == 1) &&
		    (dmc->cache_mode != FLASHCACHE_WRITE_BACK)) {
			printk(KERN_ERR "Write Cache Setting only valid with WRITE_BACK %d\n",
			       dmc->write_only_cache);
			ti->error = "flashcache: Invalid Write Cache Setting";
			r = -EINVAL;
			goto bad3;
		}
		if (dmc->write_only_cache < 0 || dmc->write_only_cache > 1) {
			printk(KERN_ERR "Invalid Write Cache Setting %d\n",
			       dmc->write_only_cache);
			ti->error = "flashcache: Invalid Write Cache Setting";
			r = -EINVAL;
			goto bad3;
		}
	}

	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) {
		if (argc >= 11) {
			if (sscanf(argv[10], "%u", &dmc->md_block_size) != 1) {
				ti->error = "flashcache: Invalid metadata block size";
				r = -EINVAL;
				goto bad3;
			}
			if (!dmc->md_block_size || (dmc->md_block_size & (dmc->md_block_size - 1)) ||
			    dmc->md_block_size > FLASHCACHE_MAX_MD_BLOCK_SIZE) {
				ti->error = "flashcache: Invalid metadata block size";
				r = -EINVAL;
				goto bad3;
			}
			if (dmc->assoc < 
			    (dmc->md_block_size * 512 / sizeof(struct flash_cacheblock))) {
				ti->error = "flashcache: Please choose a smaller metadata block size or larger assoc";
				r = -EINVAL;
				goto bad3;
			}
		}

		if (!dmc->md_block_size)
			dmc->md_block_size = DEFAULT_MD_BLOCK_SIZE;

		if (dmc->md_block_size * 512 < dmc->cache_dev->bdev->bd_block_size) {
			ti->error = "flashcache: Metadata block size must be >= cache device sector size";
			r = -EINVAL;
			goto bad3;
		}
	}

	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) {	
		if (persistence == CACHE_CREATE) {
			if (flashcache_writeback_create(dmc, 0)) {
				ti->error = "flashcache: Cache Create Failed";
				r = -EINVAL;
				goto bad3;
			}
		} else {
			if (flashcache_writeback_create(dmc, 1)) {
				ti->error = "flashcache: Cache Force Create Failed";
				r = -EINVAL;
				goto bad3;
			}
		}
	} else
		flashcache_writethrough_create(dmc);

init:
	dmc->num_sets = dmc->size >> dmc->assoc_shift;
	order = dmc->num_sets * sizeof(struct cache_set);
	dmc->cache_sets = (struct cache_set *)vmalloc(order);
	if (!dmc->cache_sets) {
		ti->error = "Unable to allocate memory";
		r = -ENOMEM;
		vfree((void *)dmc->cache);
		goto bad3;
	}				
	memset(dmc->cache_sets, 0, order);
	for (i = 0 ; i < dmc->num_sets ; i++) {
		dmc->cache_sets[i].set_fifo_next = i * dmc->assoc;
		dmc->cache_sets[i].set_clean_next = i * dmc->assoc;
		dmc->cache_sets[i].fallow_tstamp = jiffies;
		dmc->cache_sets[i].fallow_next_cleaning = jiffies;
		dmc->cache_sets[i].hotlist_lru_tail = FLASHCACHE_NULL;
		dmc->cache_sets[i].hotlist_lru_head = FLASHCACHE_NULL;
		dmc->cache_sets[i].warmlist_lru_tail = FLASHCACHE_NULL;
		dmc->cache_sets[i].warmlist_lru_head = FLASHCACHE_NULL;
		spin_lock_init(&dmc->cache_sets[i].set_spin_lock);
	}
	
	atomic_set(&dmc->hot_list_pct, FLASHCACHE_LRU_HOT_PCT_DEFAULT);
	flashcache_reclaim_init_lru_lists(dmc);
	flashcache_hash_init(dmc);
	if (flashcache_diskclean_init(dmc)) {
		ti->error = "Unable to allocate memory";
		r = -ENOMEM;
		vfree((void *)dmc->cache);
		vfree((void *)dmc->cache_sets);
		goto bad3;
	}		

	if (flashcache_kcopy_init(dmc)) {
		ti->error = "Unable to allocate memory";
		r = -ENOMEM;
		flashcache_diskclean_destroy(dmc);
		vfree((void *)dmc->cache);
		vfree((void *)dmc->cache_sets);
		goto bad3;
	}		

	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) {
		order = (dmc->md_blocks - 1) * sizeof(struct cache_md_block_head);
		dmc->md_blocks_buf = (struct cache_md_block_head *)vmalloc(order);
		if (!dmc->md_blocks_buf) {
			ti->error = "Unable to allocate memory";
			r = -ENOMEM;
			flashcache_kcopy_destroy(dmc);
			flashcache_diskclean_destroy(dmc);
			vfree((void *)dmc->cache);
			vfree((void *)dmc->cache_sets);
			goto bad3;
		}		

		for (i = 0 ; i < dmc->md_blocks - 1 ; i++) {
			dmc->md_blocks_buf[i].nr_in_prog = 0;
			dmc->md_blocks_buf[i].queued_updates = NULL;
			dmc->md_blocks_buf[i].md_io_inprog = NULL;
			spin_lock_init(&dmc->md_blocks_buf[i].md_block_lock);
		}
	}

	atomic_set(&dmc->sync_index, 0);
	atomic_set(&dmc->clean_inprog, 0);
	atomic_set(&dmc->nr_dirty, 0);
	atomic_set(&dmc->cached_blocks, 0);
	atomic_set(&dmc->pending_jobs_count, 0);
	spin_lock_init(&dmc->ioctl_lock);
	spin_lock_init(&dmc->cache_pending_q_spinlock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	ti->split_io = dmc->block_size;
#else
	ti->max_io_len = dmc->block_size;
#endif
	ti->private = dmc;

	/* Cleaning Thresholds */
	dmc->sysctl_dirty_thresh = DIRTY_THRESH_DEF;
	dmc->dirty_thresh_set = (dmc->assoc * dmc->sysctl_dirty_thresh) / 100;
	dmc->max_clean_ios_total = MAX_CLEAN_IOS_TOTAL;
	dmc->max_clean_ios_set = MAX_CLEAN_IOS_SET;

	/* Other sysctl defaults */
	dmc->sysctl_io_latency_hist = 0;
	dmc->sysctl_do_sync = 0;
	dmc->sysctl_stop_sync = 0;
	dmc->sysctl_pid_do_expiry = 0;
	dmc->sysctl_max_pids = MAX_PIDS;
	dmc->sysctl_pid_expiry_secs = PID_EXPIRY_SECS;
	dmc->sysctl_reclaim_policy = FLASHCACHE_FIFO;
	dmc->sysctl_zerostats = 0;
	dmc->sysctl_error_inject = 0;
	dmc->sysctl_fast_remove = 0;
	dmc->sysctl_cache_all = 1;
	dmc->sysctl_fallow_clean_speed = FALLOW_CLEAN_SPEED;
	if (dmc->write_only_cache == 0)
		/* Don't both fallow cleaning for write only caching */
		dmc->sysctl_fallow_delay = FALLOW_DELAY;
	dmc->sysctl_skip_seq_thresh_kb = SKIP_SEQUENTIAL_THRESHOLD;
	dmc->sysctl_clean_on_read_miss = 0;
	dmc->sysctl_clean_on_write_miss = 0;
	dmc->sysctl_lru_hot_pct = 75;
	dmc->sysctl_lru_promote_thresh = 2;
	dmc->sysctl_new_style_write_merge = 0;

	/* Sequential i/o spotting */	
	for (i = 0; i < SEQUENTIAL_TRACKER_QUEUE_DEPTH; i++) {
		dmc->seq_recent_ios[i].most_recent_sector = 0;
		dmc->seq_recent_ios[i].sequential_count = 0;
		dmc->seq_recent_ios[i].prev = (struct sequential_io *)NULL;
		dmc->seq_recent_ios[i].next = (struct sequential_io *)NULL;
		seq_io_move_to_lruhead(dmc, &dmc->seq_recent_ios[i]);
	}
	dmc->seq_io_tail = &dmc->seq_recent_ios[0];
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
	(void)wait_on_bit_lock(&flashcache_control->synch_flags, FLASHCACHE_UPDATE_LIST,
			       flashcache_wait_schedule, TASK_UNINTERRUPTIBLE);
#else
	(void)wait_on_bit_lock(&flashcache_control->synch_flags, FLASHCACHE_UPDATE_LIST,
			       TASK_UNINTERRUPTIBLE);
#endif
	dmc->next_cache = cache_list_head;
	cache_list_head = dmc;
	clear_bit(FLASHCACHE_UPDATE_LIST, &flashcache_control->synch_flags);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
	smp_mb__after_clear_bit();
#else
	smp_mb__after_atomic();
#endif
	wake_up_bit(&flashcache_control->synch_flags, FLASHCACHE_UPDATE_LIST);

	for (i = 0 ; i < dmc->size ; i++) {
		dmc->cache[i].hash_prev = FLASHCACHE_NULL;
		dmc->cache[i].hash_next = FLASHCACHE_NULL;
		if (dmc->cache[i].cache_state & VALID) {
			flashcache_hash_insert(dmc, i);
			atomic_inc(&dmc->cached_blocks);
		}
		if (dmc->cache[i].cache_state & DIRTY) {
			dmc->cache_sets[i / dmc->assoc].nr_dirty++;
			atomic_inc(&dmc->nr_dirty);
		}
		if (dmc->cache[i].cache_state & INVALID)
			flashcache_invalid_insert(dmc, i);
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	INIT_WORK(&dmc->delayed_clean, flashcache_clean_all_sets, dmc);
#else
	INIT_DELAYED_WORK(&dmc->delayed_clean, flashcache_clean_all_sets);
#endif

	dmc->whitelist_head = NULL;
	dmc->whitelist_tail = NULL;
	dmc->blacklist_head = NULL;
	dmc->blacklist_tail = NULL;
	dmc->num_whitelist_pids = 0;
	dmc->num_blacklist_pids = 0;

	flashcache_ctr_procfs(dmc);

	return 0;

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
flashcache_dtr_stats_print(struct cache_c *dmc)
{
	int read_hit_pct, write_hit_pct, dirty_write_hit_pct;
	struct flashcache_stats *stats = &dmc->flashcache_stats;
	u_int64_t  cache_pct, dirty_pct;
	char *cache_mode;
	int i;
	
	if (stats->reads > 0)
		read_hit_pct = stats->read_hits * 100 / stats->reads;
	else
		read_hit_pct = 0;
	if (stats->writes > 0) {
		write_hit_pct = stats->write_hits * 100 / stats->writes;
		dirty_write_hit_pct = stats->dirty_write_hits * 100 / stats->writes;
	} else {
		write_hit_pct = 0;
		dirty_write_hit_pct = 0;
	}
	
	DMINFO("stats: \n\treads(%lu), writes(%lu)", stats->reads, stats->writes);

	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) {
		DMINFO("\tread hits(%lu), read hit percent(%d)\n"	\
		       "\twrite hits(%lu) write hit percent(%d)\n"	\
		       "\tdirty write hits(%lu) dirty write hit percent(%d)\n" \
		       "\treplacement(%lu), write replacement(%lu)\n"	\
		       "\twrite invalidates(%lu), read invalidates(%lu)\n" ,
		       stats->read_hits, read_hit_pct,
		       stats->write_hits, write_hit_pct,
		       stats->dirty_write_hits, dirty_write_hit_pct,
		       stats->replace, stats->wr_replace, 
		       stats->wr_invalidates, stats->rd_invalidates);
#ifdef FLASHCACHE_DO_CHECKSUMS
		DMINFO("\tchecksum store(%ld), checksum valid(%ld), checksum invalid(%ld)\n",
		       stats->checksum_store, stats->checksum_valid, stats->checksum_invalid);
#endif
		DMINFO("\tpending enqueues(%lu), pending inval(%lu)\n"	\
		       "\tmetadata dirties(%lu), metadata cleans(%lu)\n" \
		       "\tmetadata batch(%lu) metadata ssd writes(%lu)\n" \
		       "\tcleanings(%lu) fallow cleanings(%lu)\n"	\
		       "\tno room(%lu) front merge(%lu) back merge(%lu)\n",
		       stats->enqueues, stats->pending_inval,
		       stats->md_write_dirty, stats->md_write_clean,
		       stats->md_write_batch, stats->md_ssd_writes,
		       stats->cleanings, stats->fallow_cleanings, 
		       stats->noroom, stats->front_merge, stats->back_merge);
	} else if (dmc->cache_mode == FLASHCACHE_WRITE_THROUGH) {
		DMINFO("\tread hits(%lu), read hit percent(%d)\n"	\
		       "\twrite hits(%lu) write hit percent(%d)\n"	\
		       "\treplacement(%lu)\n"				\
		       "\twrite invalidates(%lu), read invalidates(%lu)\n",
		       stats->read_hits, read_hit_pct,
		       stats->write_hits, write_hit_pct,
		       stats->replace,
		       stats->wr_invalidates, stats->rd_invalidates);
#ifdef FLASHCACHE_DO_CHECKSUMS
		DMINFO("\tchecksum store(%ld), checksum valid(%ld), checksum invalid(%ld)\n",
		       stats->checksum_store, stats->checksum_valid, stats->checksum_invalid);
#endif
		DMINFO("\tpending enqueues(%lu), pending inval(%lu)\n"	\
		       "\tno room(%lu)\n",
		       stats->enqueues, stats->pending_inval,
		       stats->noroom);
	} else 	{	/* WRITE_AROUND */
		DMINFO("\tread hits(%lu), read hit percent(%d)\n"	\
		       "\treplacement(%lu)\n"				\
		       "\tinvalidates(%lu)\n",
		       stats->read_hits, read_hit_pct,
		       stats->replace,
		       stats->rd_invalidates);
#ifdef FLASHCACHE_DO_CHECKSUMS
		DMINFO("\tchecksum store(%ld), checksum valid(%ld), checksum invalid(%ld)\n",
		       stats->checksum_store, stats->checksum_valid, stats->checksum_invalid);
#endif
		DMINFO("\tpending enqueues(%lu), pending inval(%lu)\n"	\
		       "\tno room(%lu)\n",
		       stats->enqueues, stats->pending_inval,
		       stats->noroom);
	}
	/* All modes */
        DMINFO("\tdisk reads(%lu), disk writes(%lu) ssd reads(%lu) ssd writes(%lu)\n" \
               "\tuncached reads(%lu), uncached writes(%lu), uncached IO requeue(%lu)\n" \
	       "\tdisk read errors(%d), disk write errors(%d) ssd read errors(%d) ssd write errors(%d)\n" \
	       "\tuncached sequential reads(%lu), uncached sequential writes(%lu)\n" \
               "\tpid_adds(%lu), pid_dels(%lu), pid_drops(%lu) pid_expiry(%lu)",
               stats->disk_reads, stats->disk_writes, stats->ssd_reads, stats->ssd_writes,
               stats->uncached_reads, stats->uncached_writes, stats->uncached_io_requeue,
               dmc->flashcache_errors.disk_read_errors, dmc->flashcache_errors.disk_write_errors, dmc->flashcache_errors.ssd_read_errors, dmc->flashcache_errors.ssd_write_errors,
	       stats->uncached_sequential_reads, stats->uncached_sequential_writes,
               stats->pid_adds, stats->pid_dels, stats->pid_drops, stats->expiry);
	if (dmc->size > 0) {
		dirty_pct = ((u_int64_t)atomic_read(&dmc->nr_dirty) * 100) / dmc->size;
		cache_pct = ((u_int64_t)atomic_read(&dmc->cached_blocks) * 100) / dmc->size;
	} else {
		cache_pct = 0;
		dirty_pct = 0;
	}
	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK)
		cache_mode = "WRITE_BACK";
	else if (dmc->cache_mode == FLASHCACHE_WRITE_THROUGH)
		cache_mode = "WRITE_THROUGH";
	else
		cache_mode = "WRITE_AROUND";
	DMINFO("conf:\n"						\
	       "\tvirt dev (%s), ssd dev (%s), disk dev (%s) cache mode(%s)\n"		\
	       "\tcapacity(%luM), associativity(%u), data block size(%uK) metadata block size(%ub)\n" \
	       "\tskip sequential thresh(%uK)\n" \
	       "\ttotal blocks(%lu), cached blocks(%d), cache percent(%d)\n" \
	       "\tdirty blocks(%d), dirty percent(%d)\n",
	       dmc->dm_vdevname, dmc->cache_devname, dmc->disk_devname,
	       cache_mode,
	       dmc->size*dmc->block_size>>11, dmc->assoc,
	       dmc->block_size>>(10-SECTOR_SHIFT), 
	       dmc->md_block_size * 512, 
	       dmc->sysctl_skip_seq_thresh_kb,
	       dmc->size, atomic_read(&dmc->cached_blocks), 
	       (int)cache_pct, atomic_read(&dmc->nr_dirty), (int)dirty_pct);
	DMINFO("\tnr_queued(%d)\n", atomic_read(&dmc->pending_jobs_count));
	DMINFO("Size Hist: ");
	for (i = 1 ; i <= 32 ; i++) {
		if (size_hist[i] > 0)
			DMINFO("%d:%llu ", i*512, size_hist[i]);
	}
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

	flashcache_dtr_procfs(dmc);

	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) {
		flashcache_sync_for_remove(dmc);
		flashcache_writeback_md_store(dmc);
	}
	if (!dmc->sysctl_fast_remove && atomic_read(&dmc->nr_dirty) > 0)
		DMERR("Could not sync %d blocks to disk, cache still dirty", 
		      atomic_read(&dmc->nr_dirty));
	DMINFO("cache jobs %d, pending jobs %d", atomic_read(&nr_cache_jobs), 
	       atomic_read(&nr_pending_jobs));
	for (i = 0 ; i < dmc->size ; i++)
		nr_queued += dmc->cache[i].nr_queued;
	DMINFO("cache queued jobs %d", nr_queued);	
	flashcache_dtr_stats_print(dmc);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
	(void)wait_on_bit_lock(&flashcache_control->synch_flags, 
			       FLASHCACHE_UPDATE_LIST,
			       flashcache_wait_schedule, 
			       TASK_UNINTERRUPTIBLE);
#else
	(void)wait_on_bit_lock(&flashcache_control->synch_flags, 
			       FLASHCACHE_UPDATE_LIST,
			       TASK_UNINTERRUPTIBLE);
#endif
	nodepp = &cache_list_head;
	while (*nodepp != NULL) {
		if (*nodepp == dmc) {
			*nodepp = dmc->next_cache;
			break;
		}
		nodepp = &((*nodepp)->next_cache);
	}
	clear_bit(FLASHCACHE_UPDATE_LIST, &flashcache_control->synch_flags);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
	smp_mb__after_clear_bit();
#else
	smp_mb__after_atomic();
#endif
	wake_up_bit(&flashcache_control->synch_flags, FLASHCACHE_UPDATE_LIST);

	flashcache_hash_destroy(dmc);
	flashcache_diskclean_destroy(dmc);
	flashcache_kcopy_destroy(dmc);
	vfree((void *)dmc->cache);
	vfree((void *)dmc->cache_sets);
	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK)
		vfree((void *)dmc->md_blocks_buf);
	flashcache_del_all_pids(dmc, FLASHCACHE_WHITELIST, 1);
	flashcache_del_all_pids(dmc, FLASHCACHE_BLACKLIST, 1);
	VERIFY(dmc->num_whitelist_pids == 0);
	VERIFY(dmc->num_blacklist_pids == 0);
	dm_put_device(ti, dmc->disk_dev);
	dm_put_device(ti, dmc->cache_dev);
	kfree(dmc);
}

void
flashcache_status_info(struct cache_c *dmc, status_type_t type,
		       char *result, unsigned int maxlen)
{
	int read_hit_pct, write_hit_pct, dirty_write_hit_pct;
	int sz = 0; /* DMEMIT */
	struct flashcache_stats *stats = &dmc->flashcache_stats;

	if (stats->reads > 0)
		read_hit_pct = stats->read_hits * 100 / stats->reads;
	else
		read_hit_pct = 0;
	if (stats->writes > 0) {
		write_hit_pct = stats->write_hits * 100 / stats->writes;
		dirty_write_hit_pct = stats->dirty_write_hits * 100 / stats->writes;
	} else {
		write_hit_pct = 0;
		dirty_write_hit_pct = 0;
	}
	DMEMIT("stats: \n\treads(%lu), writes(%lu)\n", 
	       stats->reads, stats->writes);

	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) {
		DMEMIT("\tread hits(%lu), read hit percent(%d)\n"	\
		       "\twrite hits(%lu) write hit percent(%d)\n"	\
		       "\tdirty write hits(%lu) dirty write hit percent(%d)\n" \
		       "\treplacement(%lu), write replacement(%lu)\n"	\
		       "\twrite invalidates(%lu), read invalidates(%lu)\n",
		       stats->read_hits, read_hit_pct,
		       stats->write_hits, write_hit_pct,
		       stats->dirty_write_hits, dirty_write_hit_pct,
		       stats->replace, stats->wr_replace, 
		       stats->wr_invalidates, stats->rd_invalidates);
#ifdef FLASHCACHE_DO_CHECKSUMS
		DMEMIT("\tchecksum store(%ld), checksum valid(%ld), checksum invalid(%ld)\n",
		       stats->checksum_store, stats->checksum_valid, stats->checksum_invalid);
#endif
		DMEMIT("\tpending enqueues(%lu), pending inval(%lu)\n"	\
		       "\tmetadata dirties(%lu), metadata cleans(%lu)\n" \
		       "\tmetadata batch(%lu) metadata ssd writes(%lu)\n" \
		       "\tcleanings(%lu) fallow cleanings(%lu)\n"	\
		       "\tno room(%lu) front merge(%lu) back merge(%lu)\n" \
		       "\tforce_clean_block(%lu)\n",
		       stats->enqueues, stats->pending_inval,
		       stats->md_write_dirty, stats->md_write_clean,
		       stats->md_write_batch, stats->md_ssd_writes,
		       stats->cleanings, stats->fallow_cleanings, 
		       stats->noroom, stats->front_merge, stats->back_merge,
		       stats->force_clean_block);
	} else if (dmc->cache_mode == FLASHCACHE_WRITE_THROUGH) {
		DMEMIT("\tread hits(%lu), read hit percent(%d)\n"	\
		       "\twrite hits(%lu) write hit percent(%d)\n"	\
		       "\treplacement(%lu), write replacement(%lu)\n"	\
		       "\twrite invalidates(%lu), read invalidates(%lu)\n",
		       stats->read_hits, read_hit_pct,
		       stats->write_hits, write_hit_pct,
		       stats->replace, stats->wr_replace, 
		       stats->wr_invalidates, stats->rd_invalidates);
#ifdef FLASHCACHE_DO_CHECKSUMS
		DMEMIT("\tchecksum store(%ld), checksum valid(%ld), checksum invalid(%ld)\n",
		       stats->checksum_store, stats->checksum_valid, stats->checksum_invalid);
#endif
		DMEMIT("\tpending enqueues(%lu), pending inval(%lu)\n"	\
		       "\tno room(%lu)\n",
		       stats->enqueues, stats->pending_inval,
		       stats->noroom);
	} else {	/* WRITE_AROUND */
		DMEMIT("\tread hits(%lu), read hit percent(%d)\n"	\
		       "\treplacement(%lu), write replacement(%lu)\n"	\
		       "\tinvalidates(%lu)\n",
		       stats->read_hits, read_hit_pct,
		       stats->replace, stats->wr_replace, 
		       stats->rd_invalidates);
#ifdef FLASHCACHE_DO_CHECKSUMS
		DMEMIT("\tchecksum store(%ld), checksum valid(%ld), checksum invalid(%ld)\n",
		       stats->checksum_store, stats->checksum_valid, stats->checksum_invalid);
#endif
		DMEMIT("\tpending enqueues(%lu), pending inval(%lu)\n"	\
		       "\tno room(%lu)\n",
		       stats->enqueues, stats->pending_inval,
		       stats->noroom);
	}
	/* All modes */
	DMEMIT("\tdisk reads(%lu), disk writes(%lu) ssd reads(%lu) ssd writes(%lu)\n" \
	       "\tuncached reads(%lu), uncached writes(%lu), uncached IO requeue(%lu)\n" \
	       "\tdisk read errors(%d), disk write errors(%d) ssd read errors(%d) ssd write errors(%d)\n" \
	       "\tuncached sequential reads(%lu), uncached sequential writes(%lu)\n" \
	       "\tpid_adds(%lu), pid_dels(%lu), pid_drops(%lu) pid_expiry(%lu)\n" \
	       "\tlru hot blocks(%d), lru warm blocks(%d)\n" \
	       "\tlru promotions(%lu), lru demotions(%lu)",
	       stats->disk_reads, stats->disk_writes, stats->ssd_reads, stats->ssd_writes,
	       stats->uncached_reads, stats->uncached_writes, stats->uncached_io_requeue,
               dmc->flashcache_errors.disk_read_errors, dmc->flashcache_errors.disk_write_errors, dmc->flashcache_errors.ssd_read_errors, dmc->flashcache_errors.ssd_write_errors,
	       stats->uncached_sequential_reads, stats->uncached_sequential_writes,
	       stats->pid_adds, stats->pid_dels, stats->pid_drops, stats->expiry,
	       dmc->lru_hot_blocks, dmc->lru_warm_blocks, stats->lru_promotions, stats->lru_demotions);
	if (dmc->sysctl_io_latency_hist) {
		int i;
		
		DMEMIT("\nIO Latency Histogram: \n");
		for (i = 1 ; i <= IO_LATENCY_BUCKETS ; i++) {
			DMEMIT("< %d\tusecs : %lu\n", i * IO_LATENCY_GRAN_USECS, dmc->latency_hist[i - 1]);
		}
		DMEMIT("> 10\tmsecs : %lu", dmc->latency_hist_10ms);		
	}
}

static void
flashcache_status_table(struct cache_c *dmc, status_type_t type,
			     char *result, unsigned int maxlen)
{
	u_int64_t  cache_pct, dirty_pct;
	int i;
	int sz = 0; /* DMEMIT */
	char *cache_mode;

	if (dmc->size > 0) {
		dirty_pct = ((u_int64_t)atomic_read(&dmc->nr_dirty) * 100) / dmc->size;
		cache_pct = ((u_int64_t)atomic_read(&dmc->cached_blocks) * 100) / dmc->size;
	} else {
		cache_pct = 0;
		dirty_pct = 0;
	}
	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) {
		if (dmc->write_only_cache)
			cache_mode = "WRITE_CACHE";
		else
			cache_mode = "WRITE_BACK";
	} else if (dmc->cache_mode == FLASHCACHE_WRITE_THROUGH)
		cache_mode = "WRITE_THROUGH";
	else
		cache_mode = "WRITE_AROUND";
	DMEMIT("conf:\n");
	DMEMIT("\tssd dev (%s), disk dev (%s) cache mode(%s)\n",
	       dmc->cache_devname, dmc->disk_devname,
	       cache_mode);
	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) {
		DMEMIT("\tcapacity(%luM), associativity(%u), data block size(%uK) metadata block size(%ub)\n",
		       dmc->size*dmc->block_size>>11, dmc->assoc,
		       dmc->block_size>>(10-SECTOR_SHIFT), 
		       dmc->md_block_size * 512);
	} else {
		DMEMIT("\tcapacity(%luM), associativity(%u), data block size(%uK)\n",
		       dmc->size*dmc->block_size>>11, dmc->assoc,
		       dmc->block_size>>(10-SECTOR_SHIFT));
	}
	DMEMIT("\tdisk assoc(%uK)\n",
	       dmc->disk_assoc >> (10 - SECTOR_SHIFT));
	DMEMIT("\tskip sequential thresh(%uK)\n",
	       dmc->sysctl_skip_seq_thresh_kb);
	DMEMIT("\ttotal blocks(%lu), cached blocks(%d), cache percent(%d)\n",
	       dmc->size, atomic_read(&dmc->cached_blocks),
	       (int)cache_pct);
	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) {
		DMEMIT("\tdirty blocks(%d), dirty percent(%d)\n",
		       atomic_read(&dmc->nr_dirty), (int)dirty_pct);
	}
	DMEMIT("\tnr_queued(%d)\n", atomic_read(&dmc->pending_jobs_count));
	DMEMIT("Size Hist: ");
	for (i = 1 ; i <= 32 ; i++) {
		if (size_hist[i] > 0)
			DMEMIT("%d:%llu ", i*512, size_hist[i]);
	}
#if 0
	DMEMIT("\n");
	DMEMIT("Write Clustering Hist: ");
	for (i = 0 ; i < FLASHCACHE_WRITE_CLUST_HIST_SIZE ; i++) {
		if (dmc->write_clust_hist[i] > 0)
			DMEMIT("%d:%llu ", i, dmc->write_clust_hist[i]);
	}
	DMEMIT(">=128:%llu ", dmc->write_clust_hist_ovf);	
#endif
}

/*
 * Report cache status:
 *  Output cache stats upon request of device status;
 *  Output cache configuration upon request of table status.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
void
flashcache_status(struct dm_target *ti, status_type_t type,
		  unsigned int unused_status_flags,
		  char *result, unsigned int maxlen)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0)
int
flashcache_status(struct dm_target *ti, status_type_t type,
		  unsigned int unused_status_flags,
		  char *result, unsigned int maxlen)
#else
int
flashcache_status(struct dm_target *ti, status_type_t type,
		  char *result, unsigned int maxlen)
#endif
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
	return 0;
#endif
}

static int
flashcache_iterate_devices(struct dm_target *ti,
			   iterate_devices_callout_fn fn, void *data)
{
	struct cache_c *dmc = (struct cache_c *) ti->private;
	
        int ret = 0;

	ret = fn(ti, dmc->cache_dev, 
		 0, to_sector(dmc->cache_dev->bdev->bd_inode->i_size),
		 data);
	if (!ret)
		ret = fn(ti, dmc->disk_dev, 0, ti->len, data);		
        return ret;
}

static struct target_type flashcache_target = {
	.name   = "flashcache",
	.version= {1, 0, 4},
	.module = THIS_MODULE,
	.ctr    = flashcache_ctr,
	.dtr    = flashcache_dtr,
	.map    = flashcache_map,
	.status = flashcache_status,
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
	.ioctl 	= flashcache_ioctl,
#else
	.prepare_ioctl 	= flashcache_prepare_ioctl,
	.message        = flashcache_message,
#endif
	.iterate_devices = flashcache_iterate_devices,
};

static void
flashcache_sync_for_remove(struct cache_c *dmc)
{
	do {
		atomic_set(&dmc->remove_in_prog, SLOW_REMOVE); /* Stop cleaning of sets */
		if (!dmc->sysctl_fast_remove) {
			/* 
			 * Kick off cache cleaning. client_destroy will wait for cleanings
			 * to finish.
			 */
			printk(KERN_ALERT "Cleaning %d blocks please WAIT", atomic_read(&dmc->nr_dirty));
			/* Tune up the cleaning parameters to clean very aggressively */
			dmc->max_clean_ios_total = 20;
			dmc->max_clean_ios_set = 10;
			flashcache_sync_all(dmc);
		} else {
			/* Needed to abort any in-progress cleanings, leave blocks DIRTY */
			atomic_set(&dmc->remove_in_prog, FAST_REMOVE);
			printk(KERN_ALERT "Fast flashcache remove Skipping cleaning of %d blocks", 
			       atomic_read(&dmc->nr_dirty));
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
		cancel_delayed_work(&dmc->delayed_clean);
		flush_scheduled_work();
	} while (!dmc->sysctl_fast_remove && atomic_read(&dmc->nr_dirty) > 0);
}

static int 
flashcache_notify_reboot(struct notifier_block *this,
			 unsigned long code, void *x)
{
	struct cache_c *dmc;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
	(void)wait_on_bit_lock(&flashcache_control->synch_flags, 
			       FLASHCACHE_UPDATE_LIST,
			       flashcache_wait_schedule, 
			       TASK_UNINTERRUPTIBLE);
#else
	(void)wait_on_bit_lock(&flashcache_control->synch_flags, 
			       FLASHCACHE_UPDATE_LIST,
			       TASK_UNINTERRUPTIBLE);
#endif
	for (dmc = cache_list_head ; 
	     dmc != NULL ; 
	     dmc = dmc->next_cache) {
		if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) {
			flashcache_sync_for_remove(dmc);
			flashcache_writeback_md_store(dmc);
			dm_put_device(dmc->tgt, dmc->cache_dev);
			dm_put_device(dmc->tgt, dmc->disk_dev);
		}
	}
	clear_bit(FLASHCACHE_UPDATE_LIST, &flashcache_control->synch_flags);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
	smp_mb__after_clear_bit();
#else
	smp_mb__after_atomic();
#endif
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
struct dm_kcopyd_client *flashcache_kcp_client; /* Kcopyd client for writing back data */
#else
struct kcopyd_client *flashcache_kcp_client; /* Kcopyd client for writing back data */
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
struct dm_io_client *flashcache_io_client; /* Client memory pool*/
#endif

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
	r = dm_io_get(FLASHCACHE_ASYNC_SIZE);
	if (r) {
		DMERR("flashcache_init: Could not size dm io pool");
		return r;
	}
	r = kcopyd_client_create(FLASHCACHE_COPY_PAGES, &flashcache_kcp_client);
	if (r) {
		DMERR("flashcache_init: Failed to initialize kcopyd client");
		dm_io_put(FLASHCACHE_ASYNC_SIZE);
		return r;
	}
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22) */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)) || (defined(RHEL_RELEASE_CODE) && (RHEL_RELEASE_CODE >= 1538))
	flashcache_io_client = dm_io_client_create();
#else
	flashcache_io_client = dm_io_client_create(FLASHCACHE_COPY_PAGES);
#endif
	if (IS_ERR(flashcache_io_client)) {
		DMERR("flashcache_init: Failed to initialize DM IO client");
		return r;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	r = kcopyd_client_create(FLASHCACHE_COPY_PAGES, &flashcache_kcp_client);
#elif ((LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)) && (LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0))) || (defined(RHEL_RELEASE_CODE) && (RHEL_RELEASE_CODE >= 1538) && (RHEL_RELEASE_CODE <= 1540))
	flashcache_kcp_client = dm_kcopyd_client_create();
	if ((r = IS_ERR(flashcache_kcp_client))) {
		r = PTR_ERR(flashcache_kcp_client);
	}
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)) || (defined(RHEL_RELEASE_CODE) && (RHEL_RELEASE_CODE >= 1541))
       flashcache_kcp_client = dm_kcopyd_client_create(NULL);
       if ((r = IS_ERR(flashcache_kcp_client))) {
               r = PTR_ERR(flashcache_kcp_client);
       }
#else /* .26 <= VERSION < 3.0.0 */
	r = dm_kcopyd_client_create(FLASHCACHE_COPY_PAGES, &flashcache_kcp_client);
#endif /* .26 <= VERSION < 3.0.0 */

	if (r) {
		dm_io_client_destroy(flashcache_io_client);
		DMERR("flashcache_init: Failed to initialize kcopyd client");
		return r;
	}
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22) */

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

        printk("flashcache: %s initialized\n", flashcache_sw_version);

	flashcache_module_procfs_init();
	flashcache_control = (struct flashcache_control_s *)
		kmalloc(sizeof(struct flashcache_control_s), GFP_KERNEL);
	flashcache_control->synch_flags = 0;
	register_reboot_notifier(&flashcache_notifier);
	return r;
}

/*
 * Destroy a cache target.
 */
void __exit
flashcache_exit(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	int r = dm_unregister_target(&flashcache_target);

	if (r < 0)
		DMERR("cache: unregister failed %d", r);
#else
	dm_unregister_target(&flashcache_target);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	kcopyd_client_destroy(flashcache_kcp_client);
#else
	dm_kcopyd_client_destroy(flashcache_kcp_client);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	dm_io_client_destroy(flashcache_io_client);
#else
	dm_io_put(FLASHCACHE_ASYNC_SIZE);
#endif
	unregister_reboot_notifier(&flashcache_notifier);
	flashcache_jobs_exit();
	flashcache_module_procfs_release();
	kfree(flashcache_control);
}

module_init(flashcache_init);
module_exit(flashcache_exit);

EXPORT_SYMBOL(flashcache_writeback_load);
EXPORT_SYMBOL(flashcache_writeback_create);
EXPORT_SYMBOL(flashcache_writeback_md_store);

MODULE_DESCRIPTION(DM_NAME " Facebook flash cache target");
MODULE_AUTHOR("Mohan - based on code by Ming");
MODULE_LICENSE("GPL");
