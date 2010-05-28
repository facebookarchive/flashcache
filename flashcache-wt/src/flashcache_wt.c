/****************************************************************************
 *  flashcache_wt.c
 *  FlashCache_wt: Device mapper target for block-level disk caching
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
#include <asm/checksum.h>
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
#include <linux/verify.h>
#include <linux/random.h>
#include <linux/version.h>

#include "dm.h"
#include "dm-io.h"
#include "dm-bio-list.h"
#include "flashcache_wt.h"

static struct workqueue_struct *_kcached_wq;
static struct work_struct _kcached_work;

static int cache_read_miss(struct cache_c *dmc, struct bio* bio,
			   int index);
static int cache_write(struct cache_c *dmc, 
		       struct bio* bio);
static int cache_invalidate_blocks(struct cache_c *dmc, struct bio *bio);

u_int64_t size_hist[33];

static struct kmem_cache *_job_cache;
static mempool_t *_job_pool;

static DEFINE_SPINLOCK(_job_lock);

static LIST_HEAD(_complete_jobs);
static LIST_HEAD(_io_jobs);

static u_int64_t
flashcache_wt_compute_checksum(struct bio *bio)
{
	int i;	
	u_int64_t sum = 0, *idx;
	int cnt;

	for (i = bio->bi_idx ; i < bio->bi_vcnt ; i++) {
		idx = (u_int64_t *)
			(kmap(bio->bi_io_vec[i].bv_page) + bio->bi_io_vec[i].bv_offset);
		cnt = bio->bi_io_vec[i].bv_len;
		while (cnt > 0) {
			sum += *idx++;
			cnt -= sizeof(u_int64_t);
		}
		kunmap(bio->bi_io_vec[i].bv_page);
	}
	return sum;
}

static void
flashcache_wt_store_checksum(struct kcached_job *job)
{
	u_int64_t sum;
	unsigned long flags;
	
	sum = flashcache_wt_compute_checksum(job->bio);
	spin_lock_irqsave(&job->dmc->cache_spin_lock, flags);
	job->dmc->cache[job->index].checksum = sum;
	spin_unlock_irqrestore(&job->dmc->cache_spin_lock, flags);
}

static int
flashcache_wt_validate_checksum(struct kcached_job *job)
{
	u_int64_t sum;
	int retval;
	unsigned long flags;
	
	sum = flashcache_wt_compute_checksum(job->bio);
	spin_lock_irqsave(&job->dmc->cache_spin_lock, flags);
	if (job->dmc->cache[job->index].checksum == sum) {
		job->dmc->checksum_valid++;		
		retval = 0;
	} else {
		job->dmc->checksum_invalid++;
		retval = 1;
	}
	spin_unlock_irqrestore(&job->dmc->cache_spin_lock, flags);
	return retval;
}

static int 
jobs_init(void)
{
	_job_cache = kmem_cache_create("kcached-jobs",
	                               sizeof(struct kcached_job),
	                               __alignof__(struct kcached_job),
	                               0, NULL, NULL);
	if (!_job_cache)
		return -ENOMEM;

	_job_pool = mempool_create(FLASHCACHE_WT_MIN_JOBS, mempool_alloc_slab,
	                           mempool_free_slab, _job_cache);
	if (!_job_pool) {
		kmem_cache_destroy(_job_cache);
		return -ENOMEM;
	}

	return 0;
}

static void 
jobs_exit(void)
{
	BUG_ON(!list_empty(&_complete_jobs));
	BUG_ON(!list_empty(&_io_jobs));

	mempool_destroy(_job_pool);
	kmem_cache_destroy(_job_cache);
	_job_pool = NULL;
	_job_cache = NULL;
}

/*
 * Functions to push and pop a job onto the head of a given job list.
 */
static inline struct kcached_job *
pop(struct list_head *jobs)
{
	struct kcached_job *job = NULL;
	unsigned long flags;

	spin_lock_irqsave(&_job_lock, flags);
	if (!list_empty(jobs)) {
		job = list_entry(jobs->next, struct kcached_job, list);
		list_del(&job->list);
	}
	spin_unlock_irqrestore(&_job_lock, flags);
	return job;
}

static inline void 
push(struct list_head *jobs, struct kcached_job *job)
{
	unsigned long flags;

	spin_lock_irqsave(&_job_lock, flags);
	list_add_tail(&job->list, jobs);
	spin_unlock_irqrestore(&_job_lock, flags);
}

/*
 * Note : io_callback happens from softirq() and you cannot kick off 
 * new IOs from here. Unfortunately, we have to loop back the calls 
 * to kick off new IOs to the workqueue.
 */
void 
flashcache_wt_io_callback(unsigned long error, void *context)
{
	struct kcached_job *job = (struct kcached_job *) context;
	struct cache_c *dmc = job->dmc;
	struct bio *bio;
	unsigned long flags;
	int invalid = 0;
	
	VERIFY(job != NULL);
	bio = job->bio;
	VERIFY(bio != NULL);
	DPRINTK("flashcache_wt_io_callback: %s %llu(%llu->%llu,%llu)",
		(job->rw == READ ? "READ" : "WRITE"),
		bio->bi_sector, job->disk.sector, job->cache.sector,
	        job->disk.count);
	if (error)
		DMERR("flashcache_wt_io_callback: io error %ld", error);
	if (job->rw == READSOURCE || job->rw == WRITESOURCE) {
		spin_lock_irqsave(&dmc->cache_spin_lock, flags);
		if (dmc->cache_state[job->index] != INPROG) {
			VERIFY(dmc->cache_state[job->index] == INPROG_INVALID);
			invalid++;
		}
		spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
		if (error || invalid) {
			if (invalid)
				DMERR("flashcache_wt_io_callback: cache fill invalidation, sector %llu, size %u",
				      bio->bi_sector, bio->bi_size);
			bio_endio(bio, bio->bi_size, error);
			spin_lock_irqsave(&dmc->cache_spin_lock, flags);
			dmc->cache_state[job->index] = INVALID;
			spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
			goto out;
		} else {
			/* Kick off the write to the cache */
			job->rw = WRITECACHE;
			push(&_io_jobs, job);
			queue_work(_kcached_wq, &_kcached_work);
			return;
		}
	} else if (job->rw == READCACHE) {
		spin_lock_irqsave(&dmc->cache_spin_lock, flags);
		VERIFY(dmc->cache_state[job->index] == INPROG_INVALID ||
		       dmc->cache_state[job->index] ==  CACHEREADINPROG);
		if (dmc->cache_state[job->index] == INPROG_INVALID)
			invalid++;
		spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
		if (!invalid && !error &&
		    (flashcache_wt_validate_checksum(job) == 0)) {
			/* Complete the current IO successfully */

			bio_endio(bio, bio->bi_size, 0);
			spin_lock_irqsave(&dmc->cache_spin_lock, flags);
			dmc->cache_state[job->index] = VALID;
			spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
			goto out;
		}
		/* error || invalid || bad checksum, bounce back to source device */
		job->rw = READCACHE_DONE;
		push(&_complete_jobs, job);
		queue_work(_kcached_wq, &_kcached_work);
		return;
	} else {
		VERIFY(job->rw == WRITECACHE);
		bio_endio(bio, bio->bi_size, 0);
		spin_lock_irqsave(&dmc->cache_spin_lock, flags);
		VERIFY((dmc->cache_state[job->index] == INPROG) ||
		       (dmc->cache_state[job->index] == INPROG_INVALID));
		if (error || dmc->cache_state[job->index] == INPROG_INVALID) {
			dmc->cache_state[job->index] = INVALID;
		} else {
			dmc->cache_state[job->index] = VALID;
			dmc->cached_blocks++;
		}
		spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
		DPRINTK_LITE("Cache Fill: Block %llu, index = %d: Cache state = %d",
			     dmc->cache[job->index].dbn, job->index, 
			     dmc->cache_state[job->index]);
	}
out:
	mempool_free(job, _job_pool);
	if (atomic_dec_and_test(&dmc->nr_jobs))
		wake_up(&dmc->destroyq);

}

static int 
do_io(struct kcached_job *job)
{
	int r = 0;
	struct cache_c *dmc = job->dmc;
	struct bio *bio = job->bio;

	VERIFY(job->rw == WRITECACHE);
	/* Write to cache device */
	flashcache_wt_store_checksum(job);
	dmc->checksum_store++;
	r = dm_io_async_bvec(1, &job->cache, WRITE, bio->bi_io_vec + bio->bi_idx,
			     flashcache_wt_io_callback, job);
	VERIFY(r == 0); /* In our case, dm_io_async_bvec() must always return 0 */
	return r;
}

int 
flashcache_wt_do_complete(struct kcached_job *job)
{
	struct bio *bio = job->bio;
	struct cache_c *dmc = job->dmc;
	unsigned long flags;

	VERIFY(job->rw == READCACHE_DONE);
	DPRINTK("flashcache_wt_do_complete: %llu", bio->bi_sector);
	/* error || block invalidated while reading from cache || bad checksum */
	/* Kick this IO back to the source bdev */
	bio->bi_bdev = dmc->disk_dev->bdev;
	generic_make_request(bio);
	spin_lock_irqsave(&dmc->cache_spin_lock, flags);
	dmc->cache_state[job->index] = INVALID;
	spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
	mempool_free(job, _job_pool);
	if (atomic_dec_and_test(&dmc->nr_jobs))
		wake_up(&dmc->destroyq);
	return 0;
}

static void
process_jobs(struct list_head *jobs,
	      int (*fn) (struct kcached_job *))
{
	struct kcached_job *job;

	while ((job = pop(jobs)))
		(void)fn(job);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void 
do_work(void *unused)
#else
static void 
do_work(struct work_struct *work)
#endif
{
	process_jobs(&_complete_jobs, flashcache_wt_do_complete);
	process_jobs(&_io_jobs, do_io);
}

/* DM async IO mempool sizing */
#define FLASHCACHE_WT_ASYNC_SIZE 1024

static int 
kcached_init(struct cache_c *dmc)
{
	int r;

	r = dm_io_get(FLASHCACHE_WT_ASYNC_SIZE);
	if (r) {
		DMERR("kcached_init: Could not resize dm io pool");
		return r;
	}
	init_waitqueue_head(&dmc->destroyq);
	atomic_set(&dmc->nr_jobs, 0);
	return 0;
}

void 
kcached_client_destroy(struct cache_c *dmc)
{
	/* Wait for completion of all jobs submitted by this client. */
	wait_event(dmc->destroyq, !atomic_read(&dmc->nr_jobs));
	dm_io_put(FLASHCACHE_WT_ASYNC_SIZE);
}

/*
 * Map a block from the source device to a block in the cache device.
 */
static unsigned long 
hash_block(struct cache_c *dmc, sector_t dbn)
{
	unsigned long set_number, value;

	value = (unsigned long)
		(dbn >> (dmc->block_shift + dmc->consecutive_shift));
	set_number = value % (dmc->size >> dmc->consecutive_shift);
	DPRINTK("Hash: %llu(%lu)->%lu", dbn, value, set_number);
 	return set_number;
}

static int
find_valid_dbn(struct cache_c *dmc, sector_t dbn, 
	       int start_index, int *index)
{
	int i;
	int end_index = start_index + dmc->assoc;

	for (i = start_index ; i < end_index ; i++) {
		if (dbn == dmc->cache[i].dbn &&
		    (dmc->cache_state[i] == VALID || 
		     dmc->cache_state[i] == CACHEREADINPROG || 
		     dmc->cache_state[i] == INPROG)) {
			*index = i;
			return dmc->cache_state[i];
		}
	}
	return -1;
}

static void
find_invalid_dbn(struct cache_c *dmc, int start_index, int *index)
{
	int i;
	int end_index = start_index + dmc->assoc;

	/* Find INVALID slot that we can reuse */
	for (i = start_index ; i < end_index ; i++) {
		if (dmc->cache_state[i] == INVALID) {
			*index = i;
			return;
		}
	}
}

static void
find_reclaim_dbn(struct cache_c *dmc, int start_index, int *index)
{
	int i;
	int end_index = start_index + dmc->assoc;
	int set = start_index / dmc->assoc;
	int slots_searched = 0;
	
	/* 
	 * Find the "oldest" VALID slot to recycle. 
	 * For each set, we keep track of the next "lru"
	 * slot to pick off. Each time we pick off a VALID
	 * entry to recycle we advance this pointer. So 
	 * we sweep through the set looking for next blocks
	 * to recycle. This approximates to FIFO (modulo 
	 * for blocks written through).
	 * XXX - Add LRU ala (wb) flashcache.
	 */
	i = dmc->set_lru_next[set];
	while (slots_searched < dmc->assoc) {
		VERIFY(i >= start_index);
		VERIFY(i < end_index);
		if (dmc->cache_state[i] == VALID) {
			*index = i;
			break;
		}
		slots_searched++;
		i++;
		if (i == end_index)
			i = start_index;
	}
	i++;
	if (i == end_index)
		i = start_index;
	dmc->set_lru_next[set] = i;
}

/* 
 * dbn is the starting sector, io_size is the number of sectors.
 */
static int 
cache_lookup(struct cache_c *dmc, struct bio *bio, int *index)
{
	sector_t dbn = bio->bi_sector;
	int io_size = to_sector(bio->bi_size);
	unsigned long set_number = hash_block(dmc, dbn);
	int invalid = -1, oldest_clean = -1;
	int start_index;
	int ret;

	start_index = dmc->assoc * set_number;
	DPRINTK("Cache read lookup : dbn %llu(%lu), set = %d",
		dbn, io_size, set_number);
	ret = find_valid_dbn(dmc, dbn, start_index, index);
	if (ret == VALID || ret == INPROG || ret == CACHEREADINPROG) {
		DPRINTK_LITE("Cache read lookup: Block %llu(%lu): ret %d VALID/INPROG index %d",
			     dbn, io_size, ret, *index);
		/* We found the exact range of blocks we are looking for */
		return ret;
	}
	DPRINTK_LITE("Cache read lookup: Block %llu(%lu):%d INVALID",
		     dbn, io_size, ret);
	VERIFY(ret == -1);
	find_invalid_dbn(dmc, start_index, &invalid);
	if (invalid == -1) {
		/* We didn't find an invalid entry, search for oldest valid entry */
		find_reclaim_dbn(dmc, start_index, &oldest_clean);
	}
	/* 
	 * Cache miss :
	 * We can't choose an entry marked INPROG, but choose the oldest
	 * INVALID or the oldest VALID entry.
	 */
	*index = start_index + dmc->assoc;
	if (invalid != -1) {
		DPRINTK_LITE("Cache read lookup MISS (INVALID): dbn %llu(%lu), set = %d, index = %d, start_index = %d",
			     dbn, io_size, set_number, invalid, start_index);
		*index = invalid;
	} else if (oldest_clean != -1) {
		DPRINTK_LITE("Cache read lookup MISS (VALID): dbn %llu(%lu), set = %d, index = %d, start_index = %d",
			     dbn, io_size, set_number, oldest_clean, start_index);
		*index = oldest_clean;
	} else {
		DPRINTK_LITE("Cache read lookup MISS (NOROOM): dbn %llu(%lu), set = %d",
			dbn, io_size, set_number);
	}
	if (*index < (start_index + dmc->assoc))
		return INVALID;
	else
		return -1;
}

static struct kcached_job *
new_kcached_job(struct cache_c *dmc, struct bio* bio,
		     int index)
{
	struct kcached_job *job;
	
	job = mempool_alloc(_job_pool, GFP_NOIO);
	if (job == NULL)
		return NULL;
	job->disk.bdev = dmc->disk_dev->bdev;
	job->disk.sector = bio->bi_sector;
	job->disk.count = dmc->block_size;
	job->cache.bdev = dmc->cache_dev->bdev;
	job->cache.sector = index << dmc->block_shift;
	job->cache.count = dmc->block_size;
	job->dmc = dmc;
	job->bio = bio;
	job->index = index;
	job->error = 0;
	return job;
}

static int 
cache_read_miss(struct cache_c *dmc, struct bio* bio,
		int index)
{
	struct kcached_job *job;
	unsigned long flags;

	DPRINTK("Cache Read Miss sector %llu %u bytes, index %d)",
		bio->bi_sector, bio->bi_size, index);

	job = new_kcached_job(dmc, bio, index);
	if (job == NULL) {
		/* XXX - need to bump up a stat here */	
		DMERR("cache_read_miss: Cannot allocate job\n");
		spin_lock_irqsave(&dmc->cache_spin_lock, flags);
		dmc->cache_state[index] = INVALID;
		spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
		/* Forward to source device */
		bio->bi_bdev = dmc->disk_dev->bdev;
		return DM_MAPIO_REMAPPED;
	}
	job->rw = READSOURCE; /* Fetch data from the source device */
	DPRINTK("Queue job for %llu", bio->bi_sector);
	atomic_inc(&dmc->nr_jobs);
	dm_io_async_bvec(1, &job->disk, READ,
			 bio->bi_io_vec + bio->bi_idx,
			 flashcache_wt_io_callback, job);
	return DM_MAPIO_SUBMITTED;
}

static int
cache_read(struct cache_c *dmc, struct bio *bio)
{
	int index;
	int res;
	unsigned long flags;

	DPRINTK_LITE("Got a %s for %llu  %u bytes)",
	        (bio_rw(bio) == READ ? "READ":"READA"), 
		bio->bi_sector, bio->bi_size);

	dmc->reads++;
	spin_lock_irqsave(&dmc->cache_spin_lock, flags);
	res = cache_lookup(dmc, bio, &index);
	/* Cache Hit */
	if ((res == VALID) && (dmc->cache[index].dbn == bio->bi_sector)) {
		struct kcached_job *job;
			
		dmc->cache_state[index] = CACHEREADINPROG;
		dmc->cache_hits++;
		spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
		DPRINTK_LITE("Cache read: Block %llu(%lu), index = %d:%s",
			     bio->bi_sector, bio->bi_size, index, "CACHE HIT");
		job = new_kcached_job(dmc, bio, index);
		if (job == NULL) {
			/* 
			 * Can't allocate job, bounce back to source dev 
			 * XXX - need up bump a stat here
			 */
			DMERR("cache_read(_hit): Cannot allocate job\n");
			spin_lock_irqsave(&dmc->cache_spin_lock, flags);
			dmc->cache_state[index] = VALID;
			spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
			/* Forward to source device */
			bio->bi_bdev = dmc->disk_dev->bdev;
			return DM_MAPIO_REMAPPED;
		}
		job->rw = READCACHE; /* Fetch data from the source device */
		DPRINTK("Queue job for %llu", bio->bi_sector);
		atomic_inc(&dmc->nr_jobs);
		dm_io_async_bvec(1, &job->cache, READ,
				 bio->bi_io_vec + bio->bi_idx,
				 flashcache_wt_io_callback, job);
		return DM_MAPIO_SUBMITTED;
	}
	/*
	 * In all cases except for a cache hit (and VALID), test for potential 
	 * invalidations that we need to do.
	 */
	if (cache_invalidate_blocks(dmc, bio) > 0) {
		/* A non zero return indicates an inprog invalidation */
		spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
		/* Forward to source device */
		bio->bi_bdev = dmc->disk_dev->bdev;
		return DM_MAPIO_REMAPPED;
	}
	if (res == -1 || res >= INPROG) {
		/*
		 * We either didn't find a cache slot in the set we were looking
		 * at or the block we are trying to read is being refilled into 
		 * cache.
		 */
		spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
		DPRINTK_LITE("Cache read: Block %llu(%lu):%s",
			bio->bi_sector, bio->bi_size, "CACHE MISS & NO ROOM");
		/* Forward to source device */
		bio->bi_bdev = dmc->disk_dev->bdev;
		return DM_MAPIO_REMAPPED;
	}
	/* 
	 * (res == INVALID) Cache Miss 
	 * And we found cache blocks to replace
	 * Claim the cache blocks before giving up the spinlock
	 */
	if (dmc->cache_state[index] == VALID) {
		dmc->cached_blocks--;
		dmc->replace++;
	}
	dmc->cache_state[index] = INPROG;
	dmc->cache[index].dbn = bio->bi_sector;
	spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);

	DPRINTK_LITE("Cache read: Block %llu(%lu), index = %d:%s",
		bio->bi_sector, bio->bi_size, index, "CACHE MISS & REPLACE");
	return cache_read_miss(dmc, bio, index);
}

static int
cache_invalidate_block_set(struct cache_c *dmc, int set, sector_t io_start, sector_t io_end, 
			   int rw, int *inprog_inval)
{
	int start_index, end_index, i;
	int invalidations = 0;
	
	start_index = dmc->assoc * set;
	end_index = start_index + dmc->assoc;
	for (i = start_index ; i < end_index ; i++) {
		sector_t start_dbn = dmc->cache[i].dbn;
		sector_t end_dbn = start_dbn + dmc->block_size;
		
		if (dmc->cache_state[i] == INVALID ||
		    dmc->cache_state[i] == INPROG_INVALID)
			continue;
		if ((io_start >= start_dbn && io_start < end_dbn) ||
		    (io_end >= start_dbn && io_end < end_dbn)) {
			/* We have a match */
			if (rw == WRITE)
				dmc->wr_invalidates++;
			else
				dmc->rd_invalidates++;
			invalidations++;
			if (dmc->cache_state[i] == VALID) {
				dmc->cached_blocks--;			
				dmc->cache_state[i] = INVALID;
				DPRINTK_LITE("Cache invalidate: Block %llu VALID",
					     start_dbn);
			} else if (dmc->cache_state[i] >= INPROG) {
				(*inprog_inval)++;
				dmc->cache_state[i] = INPROG_INVALID;
				DMERR("cache_invalidate_block_set: sector %llu, size %llu, rw %d",
				      io_start, io_end - io_start, rw);
				DPRINTK_LITE("Cache invalidate: Block %llu INPROG",
					     start_dbn);
			}
		}
	}
	return invalidations;
}

/* 
 * Since md will break up IO into blocksize pieces, we only really need to check 
 * the start set and the end set for overlaps.
 */
static int
cache_invalidate_blocks(struct cache_c *dmc, struct bio *bio)
{	
	sector_t io_start = bio->bi_sector;
	sector_t io_end = bio->bi_sector + (to_sector(bio->bi_size) - 1);
	int start_set, end_set;
	int inprog_inval_start = 0, inprog_inval_end = 0;
	
	start_set = hash_block(dmc, io_start);
	end_set = hash_block(dmc, io_end);
	(void)cache_invalidate_block_set(dmc, start_set, io_start, io_end,  
					 bio_data_dir(bio), &inprog_inval_start);
	if (start_set != end_set)
		cache_invalidate_block_set(dmc, end_set, io_start, io_end,  
					   bio_data_dir(bio),  &inprog_inval_end);
	return (inprog_inval_start + inprog_inval_end);
}

static int
cache_write(struct cache_c *dmc, struct bio* bio)
{
	int index;
	int res;
	unsigned long flags;
	struct kcached_job *job;

	dmc->writes++;
	spin_lock_irqsave(&dmc->cache_spin_lock, flags);
	if (cache_invalidate_blocks(dmc, bio) > 0) {
		/* A non zero return indicates an inprog invalidation */
		spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
		/* Forward to source device */
		bio->bi_bdev = dmc->disk_dev->bdev;
		return DM_MAPIO_REMAPPED;
	}
	res = cache_lookup(dmc, bio, &index);
	VERIFY(res == -1 || res == INVALID);
	if (res == -1) {
		spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
		/* Forward to source device */
		bio->bi_bdev = dmc->disk_dev->bdev;
		return DM_MAPIO_REMAPPED;
	}
	if (dmc->cache_state[index] == VALID) {
		dmc->cached_blocks--;
		dmc->cache_wr_replace++;
	}
	dmc->cache_state[index] = INPROG;
	dmc->cache[index].dbn = bio->bi_sector;
	spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
	job = new_kcached_job(dmc, bio, index);
	if (job == NULL) {
		/* XXX - need to bump up a stat here */
		DMERR("cache_write: Cannot allocate job\n");
		spin_lock_irqsave(&dmc->cache_spin_lock, flags);
		dmc->cache_state[index] = INVALID;
		spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
		/* Forward to source device */
		bio->bi_bdev = dmc->disk_dev->bdev;
		return DM_MAPIO_REMAPPED;
	}
	job->rw = WRITESOURCE; /* Write data to the source device */
	DPRINTK("Queue job for %llu", bio->bi_sector);
	atomic_inc(&job->dmc->nr_jobs);
	dm_io_async_bvec(1, &job->disk, WRITE, bio->bi_io_vec + bio->bi_idx,
			 flashcache_wt_io_callback, job);
	return DM_MAPIO_SUBMITTED;
}

/*
 * Decide the mapping and perform necessary cache operations for a bio request.
 */
int 
flashcache_wt_map(struct dm_target *ti, struct bio *bio,
		 union map_info *map_context)
{
	struct cache_c *dmc = (struct cache_c *) ti->private;
	unsigned long flags;
	int sectors = to_sector(bio->bi_size);

	if (sectors <= 32)
		size_hist[sectors]++;

	DPRINTK("Got a %s for %llu %u bytes)",
	        bio_rw(bio) == WRITE ? "WRITE" : (bio_rw(bio) == READ ?
	        "READ":"READA"), bio->bi_sector,
	        bio->bi_size);

	if (bio_barrier(bio))
		return -EOPNOTSUPP;

	VERIFY(to_sector(bio->bi_size) <= dmc->block_size);

	if (to_sector(bio->bi_size) != dmc->block_size) {
		spin_lock_irqsave(&dmc->cache_spin_lock, flags);
		(void)cache_invalidate_blocks(dmc, bio);
		spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
		/* Forward to source device */
		bio->bi_bdev = dmc->disk_dev->bdev;
		return DM_MAPIO_REMAPPED;
	}

	if (bio_data_dir(bio) == READ)
		return cache_read(dmc, bio);
	else
		return cache_write(dmc, bio);
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
static int cache_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct cache_c *dmc;
	unsigned int consecutive_blocks;
	sector_t i, order;
	sector_t data_size, dev_size;
	int r = -EINVAL;

	if (argc < 2) {
		ti->error = "flashcache-wt: Need at least 2 arguments";
		goto bad;
	}

	dmc = kmalloc(sizeof(*dmc), GFP_KERNEL);
	if (dmc == NULL) {
		ti->error = "flashcache-wt: Failed to allocate cache context";
		r = ENOMEM;
		goto bad;
	}

	dmc->tgt = ti;

	r = dm_get_device(ti, argv[0], 0, ti->len,
			  dm_table_get_mode(ti->table), &dmc->disk_dev);
	if (r) {
		ti->error = "flashcache-wt: Source device lookup failed";
		goto bad1;
	}

	r = dm_get_device(ti, argv[1], 0, 0,
			  dm_table_get_mode(ti->table), &dmc->cache_dev);
	if (r) {
		ti->error = "flashcache-wt: Cache device lookup failed";
		goto bad2;
	}

	r = kcached_init(dmc);
	if (r) {
		ti->error = "Failed to initialize kcached";
		goto bad3;
	}

	if (argc >= 3) {
		if (sscanf(argv[2], "%u", &dmc->block_size) != 1) {
			ti->error = "flashcache-wt: Invalid block size";
			r = -EINVAL;
			goto bad4;
		}
		if (!dmc->block_size || (dmc->block_size & (dmc->block_size - 1))) {
			ti->error = "flashcache-wt: Invalid block size";
			r = -EINVAL;
			goto bad4;
		}
	} else
		dmc->block_size = DEFAULT_BLOCK_SIZE;
	dmc->block_shift = ffs(dmc->block_size) - 1;
	dmc->block_mask = dmc->block_size - 1;

	/* dmc->size is specified in sectors here, and converted to blocks below */
	if (argc >= 4) {
		if (sscanf(argv[3], "%llu", &dmc->size) != 1) {
			ti->error = "flashcache-wt: Invalid cache size";
			r = -EINVAL;
			goto bad4;
		}
	} else {
		dmc->size = to_sector(dmc->cache_dev->bdev->bd_inode->i_size);
	}

	if (argc >= 5) {
		if (sscanf(argv[4], "%u", &dmc->assoc) != 1) {
			ti->error = "flashcache-wt: Invalid cache associativity";
			r = -EINVAL;
			goto bad4;
		}
		if (!dmc->assoc || (dmc->assoc & (dmc->assoc - 1)) ||
			dmc->size < dmc->assoc) {
			ti->error = "flashcache-wt: Invalid cache associativity";
			r = -EINVAL;
			goto bad4;
		}
	} else
		dmc->assoc = DEFAULT_CACHE_ASSOC;
	
	/* 
	 * Convert size (in sectors) to blocks.
	 * Then round size (in blocks now) down to a multiple of associativity 
	 */
	dmc->size /= dmc->block_size;
	dmc->size = (dmc->size / dmc->assoc) * dmc->assoc;

	dev_size = to_sector(dmc->cache_dev->bdev->bd_inode->i_size);
	data_size = dmc->size * dmc->block_size;
	if (data_size > dev_size) {
		DMERR("Requested cache size exeeds the cache device's capacity" \
		      "(%llu>%llu)",
  		      data_size, dev_size);
		ti->error = "flashcache-wt: Invalid cache size";
		r = -EINVAL;
		goto bad4;
	}

	consecutive_blocks = dmc->assoc;
	dmc->consecutive_shift = ffs(consecutive_blocks) - 1;

	order = dmc->size * sizeof(struct cacheblock);
	DMINFO("Allocate %lluKB (%uB per) mem for %llu-entry cache" \
	       "(capacity:%lluMB, associativity:%u, block size:%u " \
	       "sectors(%uKB))",
	       order >> 10, sizeof(struct cacheblock), dmc->size,
	       data_size >> (20-SECTOR_SHIFT), dmc->assoc, dmc->block_size,
	       dmc->block_size >> (10-SECTOR_SHIFT));
	dmc->cache = (struct cacheblock *)vmalloc(order);
	if (!dmc->cache) {
		ti->error = "Unable to allocate memory";
		r = -ENOMEM;
		goto bad4;
	}
	dmc->cache_state = (u_int8_t *)vmalloc(dmc->size);
	if (!dmc->cache_state) {
		ti->error = "Unable to allocate memory";
		r = -ENOMEM;
		vfree((void *)dmc->cache);
		goto bad4;
	}		
	
	order = (dmc->size >> dmc->consecutive_shift) * sizeof(u_int32_t);
	dmc->set_lru_next = (u_int32_t *)vmalloc(order);
	if (!dmc->set_lru_next) {
		ti->error = "Unable to allocate memory";
		r = -ENOMEM;
		vfree((void *)dmc->cache);
		vfree((void *)dmc->cache_state);
		goto bad4;
	}				

	/* Initialize the cache structs */
	for (i = 0; i < dmc->size ; i++) {
		dmc->cache[i].dbn = 0;
		dmc->cache[i].checksum = 0;
		dmc->cache_state[i] = INVALID;
	}

	/* Initialize the point where LRU sweeps begin for each set */
	for (i = 0 ; i < (dmc->size >> dmc->consecutive_shift) ; i++)
		dmc->set_lru_next[i] = i * dmc->assoc;

	spin_lock_init(&dmc->cache_spin_lock);

	dmc->reads = 0;
	dmc->writes = 0;
	dmc->cache_hits = 0;
	dmc->replace = 0;
	dmc->wr_invalidates = 0;
	dmc->rd_invalidates = 0;
	dmc->cached_blocks = 0;
	dmc->cache_wr_replace = 0;

	dmc->checksum_store = 0;
	dmc->checksum_valid = 0;
	dmc->checksum_invalid = 0;
	
	ti->split_io = dmc->block_size;
	ti->private = dmc;

	return 0;

bad4:
	kcached_client_destroy(dmc);
bad3:
	dm_put_device(ti, dmc->cache_dev);
bad2:
	dm_put_device(ti, dmc->disk_dev);
bad1:
	kfree(dmc);
bad:
	return r;
}

/*
 * Destroy the cache mapping.
 */
static void 
cache_dtr(struct dm_target *ti)
{
	struct cache_c *dmc = (struct cache_c *) ti->private;

	kcached_client_destroy(dmc);

	if (dmc->reads + dmc->writes > 0) {
		int read_hit_pct;
		int cache_pct;

		if (dmc->reads > 0)
			read_hit_pct = dmc->cache_hits * 100 / dmc->reads;
		else
			read_hit_pct = 0;
		DMINFO("stats: \n\treads(%lu), writes(%lu)\n", dmc->reads, dmc->writes);
		DMINFO("\tcache hits(%lu), cache hit percent (%d)\n"	\
		       "\treplacement(%lu), write replacement(%lu)\n"	\
		       "\tread invalidates(%lu), write invalidates(%lu)\n" \
		       "\tchecksum store (%lu), checksum valid (%lu), checksum invalid(%lu)\n",
		       dmc->cache_hits, read_hit_pct, dmc->replace, dmc->cache_wr_replace,
		       dmc->rd_invalidates, dmc->wr_invalidates, dmc->checksum_store, 
		       dmc->checksum_valid, dmc->checksum_invalid);
		if (dmc->size > 0)
			cache_pct = (dmc->cached_blocks * 100) / dmc->size;
		else 
			cache_pct = 0;
		DMINFO("conf:\n"\
		       "\tcapacity(%lluM), associativity(%u), block size(%uK)\n" \
		       "\ttotal blocks(%u), cached blocks(%lu), cache percent(%d)\n",
		       dmc->size*dmc->block_size>>11, dmc->assoc,
		       dmc->block_size>>(10-SECTOR_SHIFT), 
		       dmc->size, dmc->cached_blocks, cache_pct);
	}

	vfree((void *)dmc->cache);
	vfree((void *)dmc->cache_state);
	vfree((void *)dmc->set_lru_next);

	dm_put_device(ti, dmc->disk_dev);
	dm_put_device(ti, dmc->cache_dev);
	kfree(dmc);
}

static void
flashcache_wt_status_info(struct cache_c *dmc, status_type_t type,
			 char *result, unsigned int maxlen)
{
	int read_hit_pct;
	int sz = 0; /* DMEMIT */

	if (dmc->reads > 0)
		read_hit_pct = dmc->cache_hits * 100 / dmc->reads;
	else
		read_hit_pct = 0;
	DMEMIT("stats: \n\treads(%lu), writes(%lu)\n", dmc->reads, dmc->writes);
	DMEMIT("\tcache hits(%lu), cache hit percent (%d)\n" \
	       "\treplacement(%lu), write replacement(%lu)\n" \
	       "\tread invalidates(%lu), write invalidates(%lu)\n" \
	       "\tchecksum store (%lu), checksum valid (%lu), checksum invalid(%lu)\n",
	       dmc->cache_hits, read_hit_pct, dmc->replace, dmc->cache_wr_replace,
	       dmc->rd_invalidates, dmc->wr_invalidates, dmc->checksum_store, 
	       dmc->checksum_valid, dmc->checksum_invalid);
}

static void
flashcache_wt_status_table(struct cache_c *dmc, status_type_t type,
			  char *result, unsigned int maxlen)
{
	int cache_pct;
	int i;
	int sz = 0; /* DMEMIT */

	if (dmc->size > 0)
		cache_pct = (dmc->cached_blocks * 100) / dmc->size;
	else 
		cache_pct = 0;
	DMEMIT("conf:\n"\
	       "\tcapacity(%uM), associativity(%u), block size(%uK)\n" \
	       "\ttotal blocks(%u), cached blocks(%lu), cache percent(%d)\n",
	       dmc->size*dmc->block_size>>11, dmc->assoc,
	       dmc->block_size>>(10-SECTOR_SHIFT), 
	       dmc->size, dmc->cached_blocks, cache_pct);
	DMEMIT(" Size Hist: ");
	for (i = 1 ; i <= 32 ; i++) {
		if (size_hist[i] > 0)
			DMEMIT("%d:%ld ", i*512, size_hist[i]);
	}
}

/*
 * Report cache status:
 *  Output cache stats upon request of device status;
 *  Output cache configuration upon request of table status.
 */
static int 
cache_status(struct dm_target *ti, status_type_t type,
	     char *result, unsigned int maxlen)
{
	struct cache_c *dmc = (struct cache_c *) ti->private;
	
	switch (type) {
	case STATUSTYPE_INFO:
		flashcache_wt_status_info(dmc, type, result, maxlen);
		break;
	case STATUSTYPE_TABLE:
		flashcache_wt_status_table(dmc, type, result, maxlen);
		break;
	}
	return 0;
}


/****************************************************************************
 *  Functions for manipulating a cache target.
 ****************************************************************************/

static struct target_type cache_target = {
	.name   = "flashcache-wt",
	.version= {1, 0, 1},
	.module = THIS_MODULE,
	.ctr    = cache_ctr,
	.dtr    = cache_dtr,
	.map    = flashcache_wt_map,
	.status = cache_status,
};

/*
 * Initiate a cache target.
 */
int __init 
flashcache_wt_init(void)
{
	int r;

	r = jobs_init();
	if (r)
		return r;

	_kcached_wq = create_singlethread_workqueue("kcached");
	if (!_kcached_wq) {
		DMERR("failed to start kcached");
		return -ENOMEM;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	INIT_WORK(&_kcached_work, do_work, NULL);
#else
	INIT_WORK(&_kcached_work, do_work);
#endif

	for (r = 0 ; r < 33 ; r++)
		size_hist[r] = 0;
	r = dm_register_target(&cache_target);
	if (r < 0) {
		DMERR("cache: register failed %d", r);
	}
	return r;
}

/*
 * Destroy a cache target.
 */
void 
flashcache_wt_exit(void)
{
	int r = dm_unregister_target(&cache_target);

	if (r < 0)
		DMERR("cache: unregister failed %d", r);
	jobs_exit();
	destroy_workqueue(_kcached_wq);
}

module_init(flashcache_wt_init);
module_exit(flashcache_wt_exit);

EXPORT_SYMBOL(flashcache_wt_io_callback);
EXPORT_SYMBOL(flashcache_wt_do_complete);
EXPORT_SYMBOL(flashcache_wt_map);

MODULE_DESCRIPTION(DM_NAME " Facebook Flashcache DM target");
MODULE_AUTHOR("Mohan - based on code by Ming");
MODULE_LICENSE("GPL");
