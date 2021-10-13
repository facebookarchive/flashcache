/****************************************************************************
 *  flashcache_subr.c
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
#include <linux/sort.h>
#include <linux/time.h>
#include <asm/kmap_types.h>
#include <linux/jhash.h>
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

static DEFINE_SPINLOCK(_job_lock);

extern mempool_t *_job_pool;
extern mempool_t *_pending_job_pool;

extern atomic_t nr_cache_jobs;
extern atomic_t nr_pending_jobs;

LIST_HEAD(_pending_jobs);
LIST_HEAD(_io_jobs);
LIST_HEAD(_md_io_jobs);
LIST_HEAD(_md_complete_jobs);
LIST_HEAD(_uncached_io_complete_jobs);

LIST_HEAD(_cleaning_read_complete_jobs);
LIST_HEAD(_cleaning_write_complete_jobs);

int
flashcache_cleaning_read_empty(void)
{
	return list_empty(&_cleaning_read_complete_jobs);
}

int
flashcache_cleaning_write_empty(void)
{
	return list_empty(&_cleaning_write_complete_jobs);
}

int
flashcache_pending_empty(void)
{
	return list_empty(&_pending_jobs);
}

int
flashcache_io_empty(void)
{
	return list_empty(&_io_jobs);
}

int
flashcache_md_io_empty(void)
{
	return list_empty(&_md_io_jobs);
}

int
flashcache_md_complete_empty(void)
{
	return list_empty(&_md_complete_jobs);
}

int
flashcache_uncached_io_complete_empty(void)
{
	return list_empty(&_uncached_io_complete_jobs);
}

struct kcached_job *
flashcache_alloc_cache_job(void)
{
	struct kcached_job *job;

	job = mempool_alloc(_job_pool, GFP_NOIO);
	if (likely(job))
		atomic_inc(&nr_cache_jobs);
	return job;
}

void
flashcache_free_cache_job(struct kcached_job *job)
{
	mempool_free(job, _job_pool);
	atomic_dec(&nr_cache_jobs);
}

struct pending_job *
flashcache_alloc_pending_job(struct cache_c *dmc)
{
	struct pending_job *job;

	job = mempool_alloc(_pending_job_pool, GFP_ATOMIC);
	if (likely(job))
		atomic_inc(&nr_pending_jobs);
	else
		dmc->flashcache_errors.memory_alloc_errors++;
	return job;
}

void
flashcache_free_pending_job(struct pending_job *job)
{
	mempool_free(job, _pending_job_pool);
	atomic_dec(&nr_pending_jobs);
}

int
flashcache_invalid_get(struct cache_c *dmc, int set)
{
	struct cache_set *cache_set;
	int index;
	struct cacheblock *cacheblk;

	cache_set = &dmc->cache_sets[set];
	index = cache_set->invalid_head;
	if (index == FLASHCACHE_NULL)
		return -1;
	index += (set * dmc->assoc);
	cacheblk = &dmc->cache[index];
	VERIFY(cacheblk->cache_state == INVALID);
	flashcache_invalid_remove(dmc, index);
	return index;
}

void
flashcache_invalid_insert(struct cache_c *dmc, int index)
{
	struct cache_set *cache_set;
	struct cacheblock *cacheblk;
	int set = index / dmc->assoc;
	int start_index = set * dmc->assoc;
	int set_ix = index % dmc->assoc;
	
	/* index validity checks */
	VERIFY(index >= 0);
	VERIFY(index < dmc->size);
	cacheblk = &dmc->cache[index];
	/* It has to be an INVALID block */
	VERIFY(cacheblk->cache_state == INVALID);
	/* It cannot be on the per-set hash */
	VERIFY(cacheblk->hash_prev == FLASHCACHE_NULL);
	VERIFY(cacheblk->hash_next == FLASHCACHE_NULL);
	/* Insert this block at the head of the invalid list */
	cache_set = &dmc->cache_sets[set];
	cacheblk->hash_next = cache_set->invalid_head;
	if (cache_set->invalid_head != FLASHCACHE_NULL)
		dmc->cache[start_index + cache_set->invalid_head].hash_prev = set_ix;
	cache_set->invalid_head = set_ix;
}

void
flashcache_invalid_remove(struct cache_c *dmc, int index)
{
	struct cache_set *cache_set;
	struct cacheblock *cacheblk;
	int start_index, set;

	/* index validity checks */
	VERIFY(index >= 0);
	VERIFY(index < dmc->size);
	cacheblk = &dmc->cache[index];
	/* It has to be an INVALID block */
	VERIFY(cacheblk->cache_state == INVALID);
	set = index / dmc->assoc;
	start_index = set * dmc-> assoc;
	cache_set = &dmc->cache_sets[set];
	if (cacheblk->hash_prev != FLASHCACHE_NULL) {
		dmc->cache[start_index + cacheblk->hash_prev].hash_next = 
			cacheblk->hash_next;
	} else
		cache_set->invalid_head = cacheblk->hash_next;
	if (cacheblk->hash_next != FLASHCACHE_NULL) {
		dmc->cache[start_index + cacheblk->hash_next].hash_prev = 
			cacheblk->hash_prev;
	}
	cacheblk->hash_prev = FLASHCACHE_NULL;
	cacheblk->hash_next = FLASHCACHE_NULL;
	
}

/* Cache set block hash management */
void
flashcache_hash_init(struct cache_c *dmc)
{
	struct cache_set *cache_set;
	int i, j;
	
	for (i = 0 ; i < (dmc->size >> dmc->assoc_shift) ; i++) {
		cache_set = &dmc->cache_sets[i];
		cache_set->invalid_head = FLASHCACHE_NULL;
		for (j = 0 ; j < NUM_BLOCK_HASH_BUCKETS ; j++) 
			cache_set->hash_buckets[j] = FLASHCACHE_NULL;
	}
}

void
flashcache_hash_destroy(struct cache_c *dmc)
{
}

static inline u_int16_t *
flashcache_get_hash_bucket(struct cache_c *dmc, struct cache_set *cache_set, sector_t dbn)
{
	unsigned int hash = jhash_1word(dbn, 0xfeed);
	
	return &cache_set->hash_buckets[hash % NUM_BLOCK_HASH_BUCKETS];
}

void
flashcache_hash_remove(struct cache_c *dmc, int index)
{
	struct cache_set *cache_set;
	struct cacheblock *cacheblk;
	u_int16_t *hash_bucket;
	int start_index, set;
	
	if (index == -1)
		return;
	set = index / dmc->assoc;
	cache_set = &dmc->cache_sets[set];
	cacheblk = &dmc->cache[index];
	VERIFY(cacheblk->cache_state & VALID);
	start_index = set * dmc-> assoc;
	hash_bucket = flashcache_get_hash_bucket(dmc, cache_set, cacheblk->dbn);
	if (cacheblk->hash_prev != FLASHCACHE_NULL) {
		dmc->cache[start_index + cacheblk->hash_prev].hash_next = 
			cacheblk->hash_next;
	} else
		*hash_bucket = cacheblk->hash_next;
	if (cacheblk->hash_next != FLASHCACHE_NULL) {
		dmc->cache[start_index + cacheblk->hash_next].hash_prev = 
			cacheblk->hash_prev;
	}
	cacheblk->hash_prev = FLASHCACHE_NULL;
	cacheblk->hash_next = FLASHCACHE_NULL;
}

/* Must return -1 if not found ! */
int
flashcache_hash_lookup(struct cache_c *dmc, 
		       int set,
		       sector_t dbn)
{
	struct cache_set *cache_set = &dmc->cache_sets[set];
	int index;
	struct cacheblock *cacheblk;
	u_int16_t set_ix;
#if 0
	int start_index, end_index, i;
#endif
	
	set_ix = *flashcache_get_hash_bucket(dmc, cache_set, dbn);
	while (set_ix != FLASHCACHE_NULL) {
		index = set * dmc->assoc + set_ix;
		cacheblk = &dmc->cache[index];
		/* Only VALID blocks on the hash queue */
		VERIFY(cacheblk->cache_state & VALID);
		VERIFY((cacheblk->cache_state & INVALID) == 0);
		if (dbn == cacheblk->dbn)
			return index;
		set_ix = cacheblk->hash_next;
	}
#if 0
	/*
	 * Debugging. We didn't find the block on the hash.
	 * Make sure it is NOT in this set and VALID !
	 */
	start_index = set * dmc->assoc;
	end_index = start_index + dmc->assoc;
	for (i = start_index ; i < end_index ; i++) {
		cacheblk = &dmc->cache[i];
		if (dbn == cacheblk->dbn && (cacheblk->cache_state & VALID)) {
			printk(KERN_ERR "Did not find block in hash but found block in set !\n");
			printk(KERN_ERR "cacheblk->cache_state = %x\n",
			       cacheblk->cache_state);
			VERIFY(0);
			panic("Did not find block in hash but found block in set !\n");
		}		
	}
#endif
	return -1;
}

/*
 * Cacheblock should be VALID and should NOT be on a hash bucket already.
 */
void
flashcache_hash_insert(struct cache_c *dmc, 
		       int index)
{
	struct cache_set *cache_set = &dmc->cache_sets[index / dmc->assoc];
	struct cacheblock *cacheblk;
	u_int16_t *hash_bucket;
	u_int16_t set_ix = index % dmc->assoc;
	int start_index = (index / dmc->assoc) * dmc->assoc;
	
	cacheblk = &dmc->cache[index];
	VERIFY(cacheblk->cache_state & VALID);
	hash_bucket = flashcache_get_hash_bucket(dmc, cache_set, cacheblk->dbn);
	VERIFY(cacheblk->hash_prev == FLASHCACHE_NULL);
	VERIFY(cacheblk->hash_next == FLASHCACHE_NULL);
	cacheblk->hash_prev = FLASHCACHE_NULL;
	cacheblk->hash_next = *hash_bucket;
	if (*hash_bucket != FLASHCACHE_NULL)
		dmc->cache[start_index + *hash_bucket].hash_prev = set_ix;
	*hash_bucket = set_ix;
}

#define FLASHCACHE_PENDING_JOB_HASH(INDEX)		((INDEX) % PENDING_JOB_HASH_SIZE)

/*
 * Locking Note : enq/deq pending paths can be called from softirq as well as base 
 * context. Necessary to do the irqsave/restore variants of the lock here.
 */
void 
flashcache_enq_pending(struct cache_c *dmc, struct bio* bio,
		       int index, int action, struct pending_job *job)
{
	struct pending_job **head;
	unsigned long flags;
	
	VERIFY(!in_interrupt());
	VERIFY(spin_is_locked(&dmc->cache_sets[index / dmc->assoc].set_spin_lock));
	spin_lock_irqsave(&dmc->cache_pending_q_spinlock, flags);
	head = &dmc->pending_job_hashbuckets[FLASHCACHE_PENDING_JOB_HASH(index)];
	DPRINTK("flashcache_enq_pending: Queue to pending Q Index %d %llu",
		index, bio->bi_sector);
	VERIFY(job != NULL);
	job->action = action;
	job->index = index;
	job->bio = bio;
	job->prev = NULL;
	job->next = *head;
	if (*head)
		(*head)->prev = job;
	*head = job;
	atomic_inc(&dmc->pending_jobs_count);
	spin_unlock_irqrestore(&dmc->cache_pending_q_spinlock, flags);
	dmc->cache[index].nr_queued++;
	dmc->flashcache_stats.enqueues++;
}

/*
 * Deq and move all pending jobs that match the index for this slot to list returned
 */
struct pending_job *
flashcache_deq_pending(struct cache_c *dmc, int index)
{
	struct pending_job *node, *next, *movelist = NULL;
	int moved = 0;
	struct pending_job **head;
	unsigned long flags;
	
	VERIFY(!in_interrupt());
	spin_lock_irqsave(&dmc->cache_pending_q_spinlock, flags);
	head = &dmc->pending_job_hashbuckets[FLASHCACHE_PENDING_JOB_HASH(index)];
	for (node = *head ; node != NULL ; node = next) {
		next = node->next;
		if (node->index == index) {
			/* 
			 * Remove pending job from the global list of 
			 * jobs and move it to the private list for freeing 
			 */
			if (node->prev == NULL) {
				*head = node->next;
				if (node->next)
					node->next->prev = NULL;
			} else
				node->prev->next = node->next;
			if (node->next == NULL) {
				if (node->prev)
					node->prev->next = NULL;
			} else
				node->next->prev = node->prev;
			node->prev = NULL;
			node->next = movelist;
			movelist = node;
			moved++;
		}
	}
	VERIFY(atomic_read(&dmc->pending_jobs_count) >= moved);
	atomic_sub(moved, &dmc->pending_jobs_count);
	spin_unlock_irqrestore(&dmc->cache_pending_q_spinlock, flags);
	return movelist;
}

#ifdef FLASHCACHE_DO_CHECKSUMS
int
flashcache_read_compute_checksum(struct cache_c *dmc, int index, void *block)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
	struct io_region where;
#else
	struct dm_io_region where;
#endif
	int error;
	u_int64_t sum = 0, *idx;
	int cnt;

	where.bdev = dmc->cache_dev->bdev;
	where.sector = INDEX_TO_CACHE_ADDR(dmc, index);
	where.count = dmc->block_size;
	error = flashcache_dm_io_sync_vm(dmc, &where, READ, block);
	if (error)
		return error;
	cnt = dmc->block_size * 512;
	idx = (u_int64_t *)block;
	while (cnt > 0) {
		sum += *idx++;
		cnt -= sizeof(u_int64_t);		
	}
	dmc->cache[index].checksum = sum;
	return 0;
}

u_int64_t
flashcache_compute_checksum(struct bio *bio)
{
	int i;	
	u_int64_t sum = 0, *idx;
	int cnt;
	int kmap_type;
	void *kvaddr;

	if (in_interrupt())
		kmap_type = KM_SOFTIRQ0;
	else
		kmap_type = KM_USER0;
	for (i = bio->bi_idx ; i < bio->bi_vcnt ; i++) {
		kvaddr = kmap_atomic(bio->bi_io_vec[i].bv_page, kmap_type);
		idx = (u_int64_t *)
			((char *)kvaddr + bio->bi_io_vec[i].bv_offset);
		cnt = bio->bi_io_vec[i].bv_len;
		while (cnt > 0) {
			sum += *idx++;
			cnt -= sizeof(u_int64_t);
		}
		kunmap_atomic(kvaddr, kmap_type);
	}
	return sum;
}

void
flashcache_store_checksum(struct kcached_job *job)
{
	u_int64_t sum;
	unsigned long flags;
	int set = index / dmc->assoc;
	
	sum = flashcache_compute_checksum(job->bio);
	spin_lock_irqsave(&dmc->cache_sets[set].set_spin_lock, flags);
	job->dmc->cache[job->index].checksum = sum;
	spin_unlock_irqrestore(&dmc->cache_sets[set].set_spin_lock, flags);
}

int
flashcache_validate_checksum(struct kcached_job *job)
{
	u_int64_t sum;
	int retval;
	unsigned long flags;
	int set = index / dmc->assoc;
	
	sum = flashcache_compute_checksum(job->bio);
	spin_lock_irqsave(&dmc->cache_sets[set].set_spin_lock, flags);
	if (likely(job->dmc->cache[job->index].checksum == sum)) {
		job->dmc->flashcache_stats.checksum_valid++;		
		retval = 0;
	} else {
		job->dmc->flashcache_stats.checksum_invalid++;
		retval = 1;
	}
	spin_unlock_irqrestore(&dmc->cache_sets[set].set_spin_lock, flags);
	return retval;
}
#endif

/*
 * Functions to push and pop a job onto the head of a given job list.
 */
struct kcached_job *
pop(struct list_head *jobs)
{
	struct kcached_job *job = NULL;

	spin_lock_irq(&_job_lock);
	if (!list_empty(jobs)) {
		job = list_entry(jobs->next, struct kcached_job, list);
		list_del(&job->list);
	}
	spin_unlock_irq(&_job_lock);
	return job;
}

void 
push(struct list_head *jobs, struct kcached_job *job)
{
	unsigned long flags;

	spin_lock_irqsave(&_job_lock, flags);
	list_add_tail(&job->list, jobs);
	spin_unlock_irqrestore(&_job_lock, flags);
}

void
push_pending(struct kcached_job *job)
{
	push(&_pending_jobs, job);	
}

void
push_io(struct kcached_job *job)
{
	push(&_io_jobs, job);	
}

void
push_uncached_io_complete(struct kcached_job *job)
{
	push(&_uncached_io_complete_jobs, job);	
}

void
push_md_io(struct kcached_job *job)
{
	push(&_md_io_jobs, job);	
}

void
push_md_complete(struct kcached_job *job)
{
	push(&_md_complete_jobs, job);	
}

void 
push_cleaning(struct list_head *jobs, struct flashcache_copy_job *job)
{
	unsigned long flags;

	spin_lock_irqsave(&_job_lock, flags);
	list_add_tail(&job->list, jobs);
	spin_unlock_irqrestore(&_job_lock, flags);
}

struct flashcache_copy_job *
pop_cleaning(struct list_head *jobs)
{
	struct flashcache_copy_job *job = NULL;

	spin_lock_irq(&_job_lock);
	if (!list_empty(jobs)) {
		job = list_entry(jobs->next, struct flashcache_copy_job, list);
		list_del(&job->list);
	}
	spin_unlock_irq(&_job_lock);
	return job;
}

void
push_cleaning_read_complete(struct flashcache_copy_job *job)
{
	push_cleaning(&_cleaning_read_complete_jobs, job);
}

void
push_cleaning_write_complete(struct flashcache_copy_job *job)
{
	push_cleaning(&_cleaning_write_complete_jobs, job);
}

#define FLASHCACHE_YIELD	32

static void
process_jobs(struct list_head *jobs,
	     void (*fn) (struct kcached_job *))
{
	struct kcached_job *job;
	int done = 0;

	while ((job = pop(jobs))) {
		if (done++ >= FLASHCACHE_YIELD) {
			yield();
			done = 0;
		}
		(void)fn(job);
	}
}

static void
process_clean_jobs(struct list_head *jobs,
		   void (*fn) (struct flashcache_copy_job *))
{
	struct flashcache_copy_job *job;
	int done = 0;

	while ((job = pop_cleaning(jobs))) {
		if (done++ >= FLASHCACHE_YIELD) {
			yield();
			done = 0;
		}
		(void)fn(job);
	}
}

void 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
do_work(void *unused)
#else
do_work(struct work_struct *unused)
#endif
{
	process_jobs(&_md_complete_jobs, flashcache_md_write_done);
	process_jobs(&_pending_jobs, flashcache_do_pending);
	process_jobs(&_md_io_jobs, flashcache_md_write_kickoff);
	process_jobs(&_io_jobs, flashcache_do_io);
	process_jobs(&_uncached_io_complete_jobs, flashcache_uncached_io_complete);
	process_clean_jobs(&_cleaning_read_complete_jobs, flashcache_clean_write_kickoff);
	process_clean_jobs(&_cleaning_write_complete_jobs, flashcache_clean_md_write_kickoff);	
}

struct kcached_job *
new_kcached_job(struct cache_c *dmc, struct bio* bio, int index)
{
	struct kcached_job *job;

	job = flashcache_alloc_cache_job();
	if (unlikely(job == NULL)) {
		dmc->flashcache_errors.memory_alloc_errors++;
		return NULL;
	}
	job->dmc = dmc;
	job->index = index;
	job->job_io_regions.cache.bdev = dmc->cache_dev->bdev;
	if (index != -1) {
		job->job_io_regions.cache.sector = INDEX_TO_CACHE_ADDR(dmc, index);
		job->job_io_regions.cache.count = dmc->block_size;	
	}
	job->error = 0;	
	job->bio = bio;
	job->job_io_regions.disk.bdev = dmc->disk_dev->bdev;
	if (index != -1) {
		job->job_io_regions.disk.sector = dmc->cache[index].dbn;
		job->job_io_regions.disk.count = dmc->block_size;
	} else {
		job->job_io_regions.disk.sector = bio->bi_sector;
		job->job_io_regions.disk.count = to_sector(bio->bi_size);
	}
	job->next = NULL;
	job->md_block = NULL;
	if (dmc->sysctl_io_latency_hist)
		do_gettimeofday(&job->io_start_time);
	else {
		job->io_start_time.tv_sec = 0;
		job->io_start_time.tv_usec = 0;
	}
	return job;
}

static void
flashcache_record_latency(struct cache_c *dmc, struct timeval *start_tv)
{
	struct timeval latency;
	int64_t us;
	
	do_gettimeofday(&latency);
	latency.tv_sec -= start_tv->tv_sec;
	latency.tv_usec -= start_tv->tv_usec;	
	us = latency.tv_sec * USEC_PER_SEC + latency.tv_usec;
	us /= IO_LATENCY_GRAN_USECS;	/* histogram 250us gran, scale 10ms total */
	if (us < IO_LATENCY_BUCKETS)
		/* < 10ms latency, track it */
		dmc->latency_hist[us]++;
	else
		/* else count it in 10ms+ bucket */
		dmc->latency_hist_10ms++;
}

void
flashcache_bio_endio(struct bio *bio, int error, 
		     struct cache_c *dmc, struct timeval *start_time)
{
	if (unlikely(dmc->sysctl_io_latency_hist && 
		     start_time != NULL && 
		     start_time->tv_sec != 0))
		flashcache_record_latency(dmc, start_time);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	bio_endio(bio, bio->bi_size, error);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
	bio_endio(bio, error);
#else
	bio->bi_error = error;
	bio_endio(bio);
#endif	
}

static int 
cmp_dbn(const void *a, const void *b)
{
	if (((struct dbn_index_pair *)a)->dbn < ((struct dbn_index_pair *)b)->dbn)
		return -1;
	else
		return 1;
}

static void
swap_dbn_index_pair(void *a, void *b, int size)
{
	struct dbn_index_pair temp;
	
	temp = *(struct dbn_index_pair *)a;
	*(struct dbn_index_pair *)a = *(struct dbn_index_pair *)b;
	*(struct dbn_index_pair *)b = temp;
}

/* 
 * We have a list of blocks to write out to disk.
 * 1) Sort the blocks by dbn.
 * 2) (sysctl'able) See if there are any other blocks in the same set
 * that are contig to any of the blocks in step 1. If so, include them
 * in our "to write" set, maintaining sorted order.
 * Has to be called under the cache spinlock !
 */
void
flashcache_merge_writes(struct cache_c *dmc, struct dbn_index_pair *writes_list, 
			struct dbn_index_pair *set_dirty_list,
			int *nr_writes, int set)
{
	int dirty_blocks_in = *nr_writes;
	struct cacheblock *cacheblk;
	int i;
	int neighbor;

	VERIFY(spin_is_locked(&dmc->cache_sets[set].set_spin_lock));
	if (unlikely(*nr_writes == 0))
		return;
	/*
	 * Loop over the blocks, searching for neighbors backwards and forwards.
	 * When we find a neighbor, tack it onto writes_list.
	 */
	for (i = 0 ; i < dirty_blocks_in ; i++) {
		/* Look behind and keep merging as long as we can */
		neighbor = flashcache_hash_lookup(dmc, set, writes_list[i].dbn - dmc->block_size);
		while (neighbor != -1) {
			cacheblk = &dmc->cache[neighbor];
			VERIFY(cacheblk->cache_state & VALID);
			if ((cacheblk->cache_state & (DIRTY | BLOCK_IO_INPROG)) == DIRTY) {
				/* Found a dirty neighbor. Add it to the writes_list */
				cacheblk->cache_state |= DISKWRITEINPROG;
				flashcache_clear_fallow(dmc, neighbor);
				VERIFY(*nr_writes < dmc->assoc);
				writes_list[*nr_writes].index = neighbor;
				writes_list[*nr_writes].dbn = cacheblk->dbn;
				(*nr_writes)++;
				dmc->flashcache_stats.back_merge++;
				neighbor = flashcache_hash_lookup(dmc, set, cacheblk->dbn - dmc->block_size);
			} else
				neighbor = -1;
		}
		/* Look forward and keep merging as long as we can */
		neighbor = flashcache_hash_lookup(dmc, set, writes_list[i].dbn + dmc->block_size);
		while (neighbor != -1) {
			cacheblk = &dmc->cache[neighbor];
			VERIFY(cacheblk->cache_state & VALID);
			if ((cacheblk->cache_state & (DIRTY | BLOCK_IO_INPROG)) == DIRTY) {
				/* Found a dirty neighbor. Add it to the writes_list */
				cacheblk->cache_state |= DISKWRITEINPROG;
				flashcache_clear_fallow(dmc, neighbor);
				VERIFY(*nr_writes < dmc->assoc);
				writes_list[*nr_writes].index = neighbor;
				writes_list[*nr_writes].dbn = cacheblk->dbn;
				(*nr_writes)++;
				dmc->flashcache_stats.front_merge++;
				neighbor = flashcache_hash_lookup(dmc, set, cacheblk->dbn + dmc->block_size);
			} else
				neighbor = -1;
		}
	}
	/* This may be unnecessary. But return the list of blocks to write out sorted */
	sort(writes_list, *nr_writes, sizeof(struct dbn_index_pair), cmp_dbn, swap_dbn_index_pair);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
extern struct dm_io_client *flashcache_io_client; /* Client memory pool*/
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
int 
flashcache_dm_io_async_vm(struct cache_c *dmc, unsigned int num_regions, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
			  struct io_region *where, 
#else
			  struct dm_io_region *where, 
#endif
			  int rw,
			  void *data, io_notify_fn fn, void *context)
{
	unsigned long error_bits = 0;
	int error;
	struct dm_io_request io_req = {
		.bi_rw = rw,
		.mem.type = DM_IO_VMA,
		.mem.ptr.vma = data,
		.mem.offset = 0,
		.notify.fn = fn,
		.notify.context = context,
		.client = flashcache_io_client,
	};

	error = dm_io(&io_req, 1, where, &error_bits);
	if (error)
		return error;
	if (error_bits)
		return error_bits;
	return 0;
}
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,29)
/*
 * Wrappers for doing DM sync IO, using DM async IO.
 * It is a shame we need do this, but DM sync IO is interruptible :(
 * And we want uninterruptible disk IO :)
 * 
 * This is fixed in 2.6.30, where sync DM IO is uninterruptible.
 */
#define FLASHCACHE_DM_IO_SYNC_INPROG	0x01

static DECLARE_WAIT_QUEUE_HEAD(flashcache_dm_io_sync_waitqueue);
static DEFINE_SPINLOCK(flashcache_dm_io_sync_spinlock);

struct flashcache_dm_io_sync_state {
	int			error;
	int			flags;
};

static void
flashcache_dm_io_sync_vm_callback(unsigned long error, void *context)
{
	struct flashcache_dm_io_sync_state *state = 
		(struct flashcache_dm_io_sync_state *)context;
	unsigned long flags;
	
	spin_lock_irqsave(&flashcache_dm_io_sync_spinlock, flags);
	state->flags &= ~FLASHCACHE_DM_IO_SYNC_INPROG;
	state->error = error;
	wake_up(&flashcache_dm_io_sync_waitqueue);
	spin_unlock_irqrestore(&flashcache_dm_io_sync_spinlock, flags);
}

int
flashcache_dm_io_sync_vm(struct cache_c *dmc, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
			 struct io_region *where, 
#else
			  struct dm_io_region *where, 
#endif
			 int rw, void *data)
{
        DEFINE_WAIT(wait);
	struct flashcache_dm_io_sync_state state;

	state.error = -EINTR;
	state.flags = FLASHCACHE_DM_IO_SYNC_INPROG;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
	dm_io_async_vm(1, where, rw, data, flashcache_dm_io_sync_vm_callback, &state);
#else
	flashcache_dm_io_async_vm(dmc, 1, where, rw, data, flashcache_dm_io_sync_vm_callback, &state);
#endif
	spin_lock_irq(&flashcache_dm_io_sync_spinlock);
	while (state.flags & FLASHCACHE_DM_IO_SYNC_INPROG) {
		prepare_to_wait(&flashcache_dm_io_sync_waitqueue, &wait, 
				TASK_UNINTERRUPTIBLE);
		spin_unlock_irq(&flashcache_dm_io_sync_spinlock);
		schedule();
		spin_lock_irq(&flashcache_dm_io_sync_spinlock);
	}
	finish_wait(&flashcache_dm_io_sync_waitqueue, &wait);
	spin_unlock_irq(&flashcache_dm_io_sync_spinlock);
	return state.error;
}
#else
int
flashcache_dm_io_sync_vm(struct cache_c *dmc, struct dm_io_region *where, int rw, void *data)
{
	unsigned long error_bits = 0;
	int error;
	struct dm_io_request io_req = {
		.bi_rw = rw,
		.mem.type = DM_IO_VMA,
		.mem.ptr.vma = data,
		.mem.offset = 0,
		.notify.fn = NULL,
		.client = flashcache_io_client,
	};

	error = dm_io(&io_req, 1, where, &error_bits);
	if (error)
		return error;
	if (error_bits)
		return error_bits;
	return 0;
}
#endif

void
flashcache_update_sync_progress(struct cache_c *dmc)
{
	u_int64_t dirty_pct;
	
	if (dmc->flashcache_stats.cleanings % 1000)
		return;
	if (!atomic_read(&dmc->nr_dirty) || !dmc->size || !printk_ratelimit())
		return;
	dirty_pct = ((u_int64_t)atomic_read(&dmc->nr_dirty) * 100) / dmc->size;
	printk(KERN_INFO "Flashcache: Cleaning %d Dirty blocks, Dirty Blocks pct %llu%%", 
	       atomic_read(&dmc->nr_dirty), dirty_pct);
	printk(KERN_INFO "\r");
}


#define NUM_DISKCLEAN_BLOCKS	32

int
flashcache_diskclean_init(struct cache_c *dmc)
{
	int i;
	void *buf;
	struct diskclean_buf_ *diskclean_buf;

	dmc->diskclean_buf_head = NULL;
	spin_lock_init(&dmc->diskclean_list_lock);
	/* Allocate the buffers and push them onto the list */
	for (i = 0 ; i < NUM_DISKCLEAN_BLOCKS ; i++) {
		buf = vmalloc(dmc->assoc * sizeof(struct dbn_index_pair));
		if (!buf) {
			/* Free everything allocated up to now and return error */
			flashcache_diskclean_destroy(dmc);
			return 1;
		}
		diskclean_buf = (struct diskclean_buf_ *)buf;
		diskclean_buf->next = dmc->diskclean_buf_head;
		dmc->diskclean_buf_head = diskclean_buf;
	}
	return 0;
}

void
flashcache_diskclean_destroy(struct cache_c *dmc)
{
	struct diskclean_buf_ *diskclean_buf, *next;

	diskclean_buf = dmc->diskclean_buf_head;
	while (diskclean_buf != NULL) {
		next = diskclean_buf->next;
		vfree(diskclean_buf);
		diskclean_buf = next;
	}
}

int
flashcache_diskclean_alloc(struct cache_c *dmc, 
			   struct dbn_index_pair **buf1, struct dbn_index_pair **buf2)
{
	unsigned long flags;
	int retval;
	
	*buf1 = NULL;
	*buf2 = NULL;
	spin_lock_irqsave(&dmc->diskclean_list_lock, flags);
	if (dmc->diskclean_buf_head == NULL ||
	    dmc->diskclean_buf_head->next == NULL) {
		retval = ENOMEM;
		goto out;
	}
	*buf1 = (struct dbn_index_pair *)dmc->diskclean_buf_head;
	*buf2 = (struct dbn_index_pair *)dmc->diskclean_buf_head->next;
	dmc->diskclean_buf_head = dmc->diskclean_buf_head->next->next;
	retval = 0;
out:
	spin_unlock_irqrestore(&dmc->diskclean_list_lock, flags);
	return retval;
}

void
flashcache_diskclean_free(struct cache_c *dmc, struct dbn_index_pair *buf1, struct dbn_index_pair *buf2)
{
	unsigned long flags;
	struct diskclean_buf_ *diskclean_buf;

	VERIFY(buf1 != NULL);
	VERIFY(buf2 != NULL);	
	spin_lock_irqsave(&dmc->diskclean_list_lock, flags);
	diskclean_buf = (struct diskclean_buf_ *)buf1;
	diskclean_buf->next = dmc->diskclean_buf_head;
	dmc->diskclean_buf_head = diskclean_buf;
	diskclean_buf = (struct diskclean_buf_ *)buf2;
	diskclean_buf->next = dmc->diskclean_buf_head;
	dmc->diskclean_buf_head = diskclean_buf;
	spin_unlock_irqrestore(&dmc->diskclean_list_lock, flags);
}

EXPORT_SYMBOL(flashcache_alloc_cache_job);
EXPORT_SYMBOL(flashcache_free_cache_job);
EXPORT_SYMBOL(flashcache_alloc_pending_job);
EXPORT_SYMBOL(flashcache_free_pending_job);
EXPORT_SYMBOL(pop);
EXPORT_SYMBOL(push);
EXPORT_SYMBOL(push_pending);
EXPORT_SYMBOL(push_io);
EXPORT_SYMBOL(push_md_io);
EXPORT_SYMBOL(push_md_complete);
EXPORT_SYMBOL(process_jobs);
EXPORT_SYMBOL(do_work);
EXPORT_SYMBOL(new_kcached_job);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
EXPORT_SYMBOL(flashcache_dm_io_sync_vm_callback);
#endif
EXPORT_SYMBOL(flashcache_dm_io_sync_vm);
EXPORT_SYMBOL(flashcache_merge_writes);
EXPORT_SYMBOL(flashcache_enq_pending);
