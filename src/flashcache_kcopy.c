/****************************************************************************
 *  flashcache_kcopy.c
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
#include <linux/pid.h>
#include <linux/jhash.h>
#include <linux/vmalloc.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,21)
#include <linux/device-mapper.h>
#include <linux/bio.h>
#endif
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
#include <linux/dm-io.h>
#endif
#include "flashcache.h"
#include "flashcache_ioctl.h"

#ifndef DM_MAPIO_SUBMITTED
#define DM_MAPIO_SUBMITTED	0
#endif

extern struct work_struct _kcached_wq;
extern atomic_t nr_cache_jobs;

/*
 * We do the kcopy'ing ourselves from flash to disk to get better
 * disk write clustering by kicking off all the reads from flash 
 * first and then doing one very large disk write.
 */

/* 
 * There are some subtle bugs in this code where we leak copy jobs.
 * Until we fix that, disable this. 
 * To re-enable this, 
 * 1) Enable the flashcache_copy_data() call in flashcache_clean_set().
 * 2) Enable the code in _init and _destroy below.
 */

#define NUM_KCOPY_JOBS		32

int
flashcache_kcopy_init(struct cache_c *dmc)
{
#if 0	
	struct flashcache_copy_job *job;
	int i;

	dmc->kcopy_jobs_head = NULL;
	spin_lock_init(&dmc->kcopy_job_alloc_lock);
	/* Allocate the kcopy jobs and push them onto the list */
	for (i = 0 ; i < NUM_KCOPY_JOBS ; i++) {
		job = kmalloc(sizeof(struct flashcache_copy_job), GFP_NOIO);
		if (unlikely(job == NULL))
			return 1;
		job->pl_base = vmalloc(dmc->assoc * sizeof(struct page_list));
		if (unlikely(job->pl_base == NULL)) {
			kfree(job);
			flashcache_kcopy_destroy(dmc);
			return 1;
		}
		job->page_base = vmalloc(dmc->assoc * sizeof(struct page *));
		if (unlikely(job->page_base == NULL)) {
			vfree(job->pl_base);
			kfree(job);
			flashcache_kcopy_destroy(dmc);
			return 1;
		}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
		job->job_io_regions.cache = vmalloc(dmc->assoc * sizeof(struct io_region));
#else
		job->job_io_regions.cache = vmalloc(dmc->assoc * sizeof(struct dm_io_region));
#endif
		if (unlikely(job->job_io_regions.cache == NULL)) {
			vfree(job->pl_base);
			vfree(job->page_base);
			kfree(job);
			flashcache_kcopy_destroy(dmc);
			return 1;			
		}
		job->job_base = vmalloc(dmc->assoc * sizeof(struct kcached_job *));
		if (unlikely(job->job_base == NULL)) {
			vfree(job->pl_base);
			vfree(job->page_base);
			vfree(job->job_io_regions.cache);
			kfree(job);
			flashcache_kcopy_destroy(dmc);
			return 1;		
		}
		job->next = dmc->kcopy_jobs_head;
		dmc->kcopy_jobs_head = job;
	}
#else
	dmc->kcopy_jobs_head = NULL;
#endif
	return 0;
}

void
flashcache_kcopy_destroy(struct cache_c *dmc)
{
	struct flashcache_copy_job *job, *next;

	for (job = dmc->kcopy_jobs_head ; 
	     job != NULL ; 
	     job = next) {
		next = job->next;
		vfree(job->pl_base);
		vfree(job->page_base);
		vfree(job->job_io_regions.cache);
		vfree(job->job_base);
		kfree(job);
	}
}

static struct flashcache_copy_job *
alloc_flashcache_copy_job(struct cache_c *dmc)
{
	unsigned long flags;
	struct flashcache_copy_job *job;
	
	spin_lock_irqsave(&dmc->kcopy_job_alloc_lock, flags);
	job = dmc->kcopy_jobs_head;
	if (job != NULL)
		dmc->kcopy_jobs_head = job->next;
	spin_unlock_irqrestore(&dmc->kcopy_job_alloc_lock, flags);
	if (job != NULL)
		atomic_inc(&nr_cache_jobs);
	return job;
}

/* 
 * Important : This does NOT free the kcached jobs here. 
 * They will get freed separately, when metadata writes complete or when 
 * pending IOs complete. If you have not kicked off any of these things where
 * the kcached_job will get freed later, you need to free those before calling
 * into this !
 * 
 * In the pre-allocated copy_jobs scheme, we free the pages we allocated for
 * this copy, we added back the copy_job to the preallocated pool. 
 */
static void
free_flashcache_copy_job(struct cache_c *dmc, struct flashcache_copy_job *job)
{
	unsigned long flags;
	int i;

	for (i = 0 ; i < job->nr_writes ; i++)
		__free_page(job->page_base[i]);
	spin_lock_irqsave(&dmc->kcopy_job_alloc_lock, flags);
	job->next = dmc->kcopy_jobs_head;
	dmc->kcopy_jobs_head = job;
	spin_unlock_irqrestore(&dmc->kcopy_job_alloc_lock, flags);
	atomic_dec(&nr_cache_jobs);
}

struct flashcache_copy_job *
new_flashcache_copy_job(struct cache_c *dmc, 
			int nr_writes, 
			struct dbn_index_pair *writes_list)
{
	struct flashcache_copy_job *job;
	int i, j;
	
	job = alloc_flashcache_copy_job(dmc);
	if (unlikely(job == NULL))
		return NULL;
	job->dmc = dmc;
	job->nr_writes = nr_writes;
	job->reads_completed = 0;
	job->write_kickoff = 0;
	job->error = 0;
	job->pl_list_head = NULL;
	for (i = 0 ; i < nr_writes ; i++) {
		job->page_base[i] = alloc_page(GFP_NOIO);
		if (unlikely(job->page_base[i] == NULL)) {
			for (j = 0 ; j < i ; j++)
				__free_page(job->page_base[j]);
			goto nomem;
		}
		job->job_base[i] = new_kcached_job(dmc, NULL, writes_list[i].index);
		atomic_inc(&dmc->nr_jobs);
		if (unlikely(job->job_base[i] == NULL)) {
			for (j = 0 ; j <= i ; j++)
				__free_page(job->page_base[j]);
			for (j = 0 ; j < i ; j++) {
				flashcache_free_cache_job(job->job_base[i]);
				if (atomic_dec_and_test(&dmc->nr_jobs))
					wake_up(&dmc->destroyq);
			}
			goto nomem;			
		}
	}
	/* 
	 * Stuff the pages into the page_list structures.
	 * Null terminate each page_list entry, because we want to do 
	 * the individial reads first.
	 */
	for (i = 0 ; i < nr_writes ; i++) {
		job->pl_base[i].next = NULL;
		job->pl_base[i].page = job->page_base[i];
	}
	spin_lock_init(&job->copy_job_spinlock);
	for (i = 0 ; i < nr_writes ; i++) {
		job->job_io_regions.cache[i].bdev = dmc->cache_dev->bdev;
		job->job_io_regions.cache[i].sector = INDEX_TO_CACHE_ADDR(dmc, writes_list[i].index);
		job->job_io_regions.cache[i].count = dmc->block_size;
	}	
	job->job_io_regions.disk.bdev = dmc->disk_dev->bdev;
	job->job_io_regions.disk.sector = writes_list[0].dbn;
	job->job_io_regions.disk.count = dmc->block_size * nr_writes;
	return job;
nomem:
	free_flashcache_copy_job(dmc, job);
	return NULL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
extern struct dm_io_client *flashcache_io_client; /* Client memory pool*/
#endif

static int
dm_io_async_pagelist_IO(struct flashcache_copy_job *job,
			unsigned int num_regions,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
			struct io_region *where,
#else
			struct dm_io_region *where,
#endif
			io_notify_fn fn, 
			int rw,
			struct page_list *pl)
{
	struct dm_io_request iorq;

	iorq.bi_rw = rw;
	iorq.mem.type = DM_IO_PAGE_LIST;
	iorq.mem.ptr.pl = pl;
	iorq.mem.offset = 0;
	iorq.notify.fn = fn;
	iorq.notify.context = (void *)job;
	iorq.client = flashcache_io_client;
	return dm_io(&iorq, num_regions, where, NULL);
}

void
flashcache_handle_read_write_error(struct flashcache_copy_job *job)
{
	struct kcached_job *io_error_job;
	struct cache_c *dmc = job->dmc;
	int set;
	struct cache_set *cache_set;
	int i, index;

	DMERR("flashcache: Disk writeback failed ! read/write error %lu", 
	      job->job_io_regions.disk.sector);	
	index = CACHE_ADDR_TO_INDEX(dmc, 
				    job->job_io_regions.cache[0].sector);
	set = index / dmc->assoc;
	cache_set = &dmc->cache_sets[set];
	for (i = 0 ; i < job->nr_writes ; i++) {
		index = CACHE_ADDR_TO_INDEX(dmc, 
					    job->job_io_regions.cache[i].sector);
		io_error_job = job->job_base[i];
		io_error_job->action = WRITEDISK;
		spin_lock_irq(&cache_set->set_spin_lock);
		VERIFY(dmc->cache[index].cache_state & (DISKWRITEINPROG | VALID | DIRTY));
		VERIFY(cache_set->clean_inprog > 0);
		cache_set->clean_inprog--;
		VERIFY(atomic_read(&dmc->clean_inprog) > 0);
		atomic_dec(&dmc->clean_inprog);
		spin_unlock_irq(&cache_set->set_spin_lock);
		io_error_job->error = -EIO;
		flashcache_do_pending(io_error_job);
	}
	free_flashcache_copy_job(dmc, job);
	flashcache_clean_set(dmc, set, 0); /* Kick off more cleanings */
	dmc->flashcache_stats.cleanings++;
}

void
flashcache_clean_md_write_kickoff(struct flashcache_copy_job *job)
{
	struct kcached_job *io_complete_job;
	struct cache_c *dmc = job->dmc;
	int set;
	struct cache_set *cache_set;
	int i, index;

	/* If the write errored, clean up */
	if (unlikely(job->error))
		flashcache_handle_read_write_error(job);
	else {
		index = CACHE_ADDR_TO_INDEX(dmc, 
					    job->job_io_regions.cache[0].sector);
		set = index / dmc->assoc;
		cache_set = &dmc->cache_sets[set];
		for (i = 0 ; i < job->nr_writes ; i++) {
			index = CACHE_ADDR_TO_INDEX(dmc, 
						    job->job_io_regions.cache[i].sector);
			io_complete_job = job->job_base[i];
			io_complete_job->action = WRITEDISK;
			spin_lock_irq(&cache_set->set_spin_lock);
			VERIFY(dmc->cache[index].cache_state & (DISKWRITEINPROG | VALID | DIRTY));
			spin_unlock_irq(&cache_set->set_spin_lock);
			flashcache_md_write(io_complete_job);
		}
		free_flashcache_copy_job(dmc, job);
	}
}

void
flashcache_copy_data_write_callback(unsigned long error, void *context)
{
	struct flashcache_copy_job *job = 
		(struct flashcache_copy_job *)context;	

	if (error)
		job->dmc->flashcache_errors.disk_write_errors++;
	job->error = error;
	push_cleaning_write_complete(job);
	schedule_work(&_kcached_wq);
}

void
flashcache_clean_write_kickoff(struct flashcache_copy_job *job)
{
	int i;
	
	/*
	 * If any of the reads errored, DO NOT kick off the write at all.
	 * Do cleanup here instead !
	 */
	if (unlikely(job->error))
		flashcache_handle_read_write_error(job);
	else {
		/* 
		 * Need to kick off the write.
		 * First chain all of the pages in the page linked list.
		 */
		for (i = 0 ; i < job->nr_writes - 1 ; i++)
			job->pl_base[i].next = &job->pl_base[i + 1];
		job->pl_list_head = &job->pl_base[0];
		(void)dm_io_async_pagelist_IO(job,
					      1,
					      &job->job_io_regions.disk,
					      flashcache_copy_data_write_callback,
					      WRITE,
					      job->pl_list_head);
	}
}

/*
 * Handle single read completion. 
 * When all of the reads complete, we kick off the write
 */
void
flashcache_copy_data_read_callback(unsigned long error, void *context)
{
	struct flashcache_copy_job *job = 
		(struct flashcache_copy_job *)context;
	unsigned long flags;
	int do_write = 0;
	
	spin_lock_irqsave(&job->copy_job_spinlock, flags);
	VERIFY(job->reads_completed < job->nr_writes);
	job->reads_completed++;
	if ((job->reads_completed == job->nr_writes) &&
	    (job->write_kickoff == 0)) {
		do_write = 1;
		job->write_kickoff = 1;
	}
	/* 
	 * If any of the reads return an error, we abort the entire cleaning 
	 * operation. Stick the error in the job and let the write handle it.
	 * We let ALL of the reads complete and then handle the error when the
	 * last read completes.
	 */
	if (error) {
		job->dmc->flashcache_errors.ssd_read_errors++;
		job->error = error;
	}
	spin_unlock_irqrestore(&job->copy_job_spinlock, flags);
	if (do_write) {
		push_cleaning_read_complete(job);
		schedule_work(&_kcached_wq);
	}
}

static void
flashcache_verify_chain(struct cache_c *dmc, 
			int nr_writes, 
			struct dbn_index_pair *writes_list)
{
	int i;
	
	for (i = 0 ; i < nr_writes - 1 ; i++)
		if (writes_list[i].dbn + dmc->block_size != writes_list[i+1].dbn)
			panic("flashcache_verify_chain: chain not contig\n");
}

int
flashcache_copy_data_one_chain(struct cache_c *dmc, 
			       struct cache_set *cache_set,
			       int nr_writes, 
			       struct dbn_index_pair *writes_list)
{
	struct flashcache_copy_job *job;
	int i, index;
	struct cacheblock *cacheblk;
	int device_removal = 0;

	flashcache_verify_chain(dmc, nr_writes, writes_list);
	job = new_flashcache_copy_job(dmc, nr_writes, writes_list);
	if (unlikely(atomic_read(&dmc->remove_in_prog) == FAST_REMOVE)) {
		DMERR("flashcache: Set cleaning aborted for device removal");
		if (job) {
			/* Free the individual kcached jobs first */
			for (i = 0 ; i < nr_writes ; i++) {
				flashcache_free_cache_job(job->job_base[i]);
				if (atomic_dec_and_test(&dmc->nr_jobs))
					wake_up(&dmc->destroyq);
			}
			free_flashcache_copy_job(dmc, job);
		}
		job = NULL;
		device_removal = 1;
	}
	if (unlikely(job == NULL)) {
		dmc->flashcache_errors.memory_alloc_errors++;
		spin_lock_irq(&cache_set->set_spin_lock);
		for (i = 0 ; i < nr_writes ; i++) {
			index = writes_list[i].index;
			cacheblk = &dmc->cache[index];
			flashcache_free_pending_jobs(dmc, cacheblk, -EIO);
			cacheblk->cache_state &= ~(BLOCK_IO_INPROG);
		}
		spin_unlock_irq(&cache_set->set_spin_lock);
		if (device_removal == 0)
			DMERR("flashcache: Dirty Writeback (for sync) failed ! Can't allocate memory");
		return 1;
	}
	/* need to kick off all the reads */
	for (i = 0 ; i < nr_writes ; i++) {
		index = writes_list[i].index;
		cacheblk = &dmc->cache[index];
		spin_lock_irq(&cache_set->set_spin_lock);
		VERIFY((cacheblk->cache_state & BLOCK_IO_INPROG) == DISKWRITEINPROG);
		VERIFY(cacheblk->cache_state & DIRTY);
		cache_set->clean_inprog++;
		atomic_inc(&dmc->clean_inprog);
		spin_unlock_irq(&cache_set->set_spin_lock);
		dmc->flashcache_stats.ssd_reads++;
		dmc->flashcache_stats.disk_writes++;
		/* Kick off DM Read */
		dm_io_async_pagelist_IO(job,
					1,
					&job->job_io_regions.cache[i],
					flashcache_copy_data_read_callback, 
					READ,
					&job->pl_base[i]);
		/* XXX - Should we do something with error DM returns ? 
		 * We don't check for DM errors elsewhere */
	}
	return 0;
}

static void
flashcache_verify_sorted(struct cache_c *dmc, 
			 int nr_writes, 
			 struct dbn_index_pair *writes_list)
{
	int i;
	
	for (i = 0 ; i < nr_writes - 1 ; i++)
		if (writes_list[i].dbn >= writes_list[i+1].dbn)
			panic("flashcache_verify_sorted: writes_list not sorted\n");
}

void
flashcache_copy_data(struct cache_c *dmc, 
		     struct cache_set *cache_set,
		     int nr_writes, 
		     struct dbn_index_pair *writes_list)
{
	int i, start_index;
	
	flashcache_verify_sorted(dmc, nr_writes, writes_list);
	start_index = 0;
	while (start_index < nr_writes) {
		i = start_index;
		while ((i < (nr_writes - 1)) &&
		       (writes_list[i+1].dbn == 
			writes_list[i].dbn + dmc->block_size))
			i++;
		/* We don't check for error return from this call
		 * because cleanups happens within copy_data_one_chain */
		(void)flashcache_copy_data_one_chain(dmc, cache_set, 
						     (i - start_index) + 1,
						     &writes_list[start_index]);
		/* Kick off cleanings for next chain */
		start_index = i + 1;
	}
}
