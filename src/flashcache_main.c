/****************************************************************************
 *  flashcache_main.c
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
#endif
#include "flashcache.h"
#include "flashcache_ioctl.h"

#ifndef DM_MAPIO_SUBMITTED
#define DM_MAPIO_SUBMITTED	0
#endif

/*
 * TODO List :
 * 1) Management of non cache pids : Needs improvement. Remove registration
 * on process exits (with  a pseudo filesstem'ish approach perhaps) ?
 * 2) Breaking up the cache spinlock : Right now contention on the spinlock
 * is not a problem. Might need change in future.
 * 3) Use the standard linked list manipulation macros instead rolling our own.
 * 4) Fix a security hole : A malicious process with 'ro' access to a file can 
 * potentially corrupt file data. This can be fixed by copying the data on a
 * cache read miss.
 */

#define FLASHCACHE_SW_VERSION "flashcache-3.1.1"
char *flashcache_sw_version = FLASHCACHE_SW_VERSION;

static void flashcache_read_miss(struct cache_c *dmc, struct bio* bio,
				 int index);
static void flashcache_write(struct cache_c *dmc, struct bio* bio);
static int flashcache_inval_blocks(struct cache_c *dmc, struct bio *bio);
static void flashcache_dirty_writeback(struct cache_c *dmc, int index);
void flashcache_sync_blocks(struct cache_c *dmc);
static void flashcache_start_uncached_io(struct cache_c *dmc, struct bio *bio);

static void flashcache_setlocks_multiget(struct cache_c *dmc, struct bio *bio);
static void flashcache_setlocks_multidrop(struct cache_c *dmc, struct bio *bio);

extern struct work_struct _kcached_wq;
extern u_int64_t size_hist[];

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
extern struct dm_kcopyd_client *flashcache_kcp_client; /* Kcopyd client for writing back data */
#else
extern struct kcopyd_client *flashcache_kcp_client; /* Kcopyd client for writing back data */
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
extern struct dm_io_client *flashcache_io_client; /* Client memory pool*/
#endif

int dm_io_async_bvec_pl(unsigned int num_regions, 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
			struct dm_io_region *where, 
#else
			struct io_region *where, 
#endif
			int rw, 
			struct page_list *pl, 
			io_notify_fn fn, 
			void *context)
{
	struct dm_io_request iorq;

	iorq.bi_rw = rw;
	iorq.mem.type = DM_IO_PAGE_LIST;
	iorq.mem.ptr.pl = pl;
	iorq.mem.offset = 0;
	iorq.notify.fn = fn;
	iorq.notify.context = context;
	iorq.client = flashcache_io_client;
	return dm_io(&iorq, num_regions, where, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
int dm_io_async_bvec(unsigned int num_regions, 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
		     struct dm_io_region *where, 
#else
		     struct io_region *where, 
#endif
		     int rw, 
		     struct bio *bio, 
		     io_notify_fn fn, 
		     void *context)
{
	struct dm_io_request iorq;

	iorq.bi_rw = rw;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	iorq.mem.type = DM_IO_BIO;
	iorq.mem.ptr.bio = bio;	
#else
	iorq.mem.type = DM_IO_BVEC;
	iorq.mem.ptr.bvec = bio->bi_io_vec + bio->bi_idx;
#endif
	iorq.notify.fn = fn;
	iorq.notify.context = context;
	iorq.client = flashcache_io_client;
	return dm_io(&iorq, num_regions, where, NULL);
}
#endif

/* 
 * A simple 2-hand clock like algorithm is used to identify dirty blocks 
 * that lie fallow in the cache and thus are candidates for cleaning. 
 * Note that we could have such fallow blocks in sets where the dirty blocks 
 * is under the configured threshold.
 * The hands are spaced fallow_delay seconds apart (one sweep runs every 
 * fallow_delay seconds).  The interval is configurable via a sysctl. 
 * Blocks are moved to DIRTY_FALLOW_1, if they are found to be in DIRTY_FALLOW_1
 * for fallow_delay seconds or more, they are moved to DIRTY_FALLOW_1 | DIRTY_FALLOW_2, 
 * at which point they are eligible for cleaning. Of course any intervening use
 * of the block within the interval turns off these 2 bits.
 * 
 * Cleaning of these blocks happens from the flashcache_clean_set() function.
 */
void
flashcache_detect_fallow(struct cache_c *dmc, int index)
{
	struct cacheblock *cacheblk = &dmc->cache[index];

	if (dmc->cache_mode != FLASHCACHE_WRITE_BACK)
		return;
	if ((cacheblk->cache_state & DIRTY) &&
	    ((cacheblk->cache_state & BLOCK_IO_INPROG) == 0)) {
		if ((cacheblk->cache_state & DIRTY_FALLOW_1) == 0)
			cacheblk->cache_state |= DIRTY_FALLOW_1;
		else if ((cacheblk->cache_state & DIRTY_FALLOW_2) == 0) {
			dmc->cache_sets[index / dmc->assoc].dirty_fallow++;
			cacheblk->cache_state |= DIRTY_FALLOW_2;
		}
	}
}

void
flashcache_clear_fallow(struct cache_c *dmc, int index)
{
	struct cacheblock *cacheblk = &dmc->cache[index];
	int set = index / dmc->assoc;
	
	if (dmc->cache_mode != FLASHCACHE_WRITE_BACK)
		return;
	if (cacheblk->cache_state & FALLOW_DOCLEAN) {
		if (cacheblk->cache_state & DIRTY_FALLOW_2) {
			VERIFY(dmc->cache_sets[set].dirty_fallow > 0);
			dmc->cache_sets[set].dirty_fallow--;
		}
		cacheblk->cache_state &= ~FALLOW_DOCLEAN;
	}
}

void 
flashcache_io_callback(unsigned long error, void *context)
{
	struct kcached_job *job = (struct kcached_job *) context;
	struct cache_c *dmc = job->dmc;
	struct bio *bio;
	unsigned long flags;
	int index = job->index;
	struct cacheblock *cacheblk = &dmc->cache[index];
	unsigned long disk_error = 0;
	struct cache_set *cache_set = &dmc->cache_sets[index / dmc->assoc];

	VERIFY(index != -1);		
	bio = job->bio;
	VERIFY(bio != NULL);
	if (unlikely(error)) {
		error = -EIO;
		DMERR("flashcache_io_callback: io error %ld block %lu action %d", 
		      error, job->job_io_regions.disk.sector, job->action);
		if (!dmc->bypass_cache && dmc->cache_mode != FLASHCACHE_WRITE_BACK) {
			DMERR("flashcache_io_callback: switching %s to BYPASS mode",
			      dmc->cache_devname);
			dmc->bypass_cache = 1;
		}
	}
	job->error = error;
	switch (job->action) {
	case READDISK:
		DPRINTK("flashcache_io_callback: READDISK  %d",
			index);
		spin_lock_irqsave(&cache_set->set_spin_lock, flags);
		if (unlikely(dmc->sysctl_error_inject & READDISK_ERROR)) {
			job->error = error = -EIO;
			dmc->sysctl_error_inject &= ~READDISK_ERROR;
		}
		VERIFY(cacheblk->cache_state & DISKREADINPROG);
		spin_unlock_irqrestore(&cache_set->set_spin_lock, flags);
		if (likely(error == 0)) {
			/* Kick off the write to the cache */
			job->action = READFILL;
			push_io(job);
			schedule_work(&_kcached_wq);
			return;
		} else {
			disk_error = -EIO;
			dmc->flashcache_errors.disk_read_errors++;			
		}
		break;
	case READCACHE:
		DPRINTK("flashcache_io_callback: READCACHE %d",
			index);
		spin_lock_irqsave(&cache_set->set_spin_lock, flags);
		if (unlikely(dmc->sysctl_error_inject & READCACHE_ERROR)) {
			job->error = error = -EIO;
			dmc->sysctl_error_inject &= ~READCACHE_ERROR;
		}
		VERIFY(cacheblk->cache_state & CACHEREADINPROG);
		spin_unlock_irqrestore(&cache_set->set_spin_lock, flags);
		if (unlikely(error))
			dmc->flashcache_errors.ssd_read_errors++;
#ifdef FLASHCACHE_DO_CHECKSUMS
		if (likely(error == 0)) {
			if (flashcache_validate_checksum(job)) {
				DMERR("flashcache_io_callback: Checksum mismatch at disk offset %lu", 
				      job->job_io_regions.disk.sector);
				error = -EIO;
			}
		}
#endif
		break;		       
	case READFILL:
		DPRINTK("flashcache_io_callback: READFILL %d",
			index);
		spin_lock_irqsave(&cache_set->set_spin_lock, flags);
		if (unlikely(dmc->sysctl_error_inject & READFILL_ERROR)) {
			job->error = error = -EIO;
			dmc->sysctl_error_inject &= ~READFILL_ERROR;
		}
		if (unlikely(error))
			dmc->flashcache_errors.ssd_write_errors++;
		VERIFY(cacheblk->cache_state & DISKREADINPROG);
		spin_unlock_irqrestore(&cache_set->set_spin_lock, flags);
		break;
	case WRITECACHE:
		DPRINTK("flashcache_io_callback: WRITECACHE %d",
			index);
		if (unlikely(dmc->sysctl_error_inject & WRITECACHE_ERROR)) {
			job->error = error = -EIO;
			dmc->sysctl_error_inject &= ~WRITECACHE_ERROR;
		}
		spin_lock_irqsave(&cache_set->set_spin_lock, flags);
		VERIFY(cacheblk->cache_state & CACHEWRITEINPROG);
		spin_unlock_irqrestore(&cache_set->set_spin_lock, flags);
		if (likely(error == 0)) {
			if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) {
#ifdef FLASHCACHE_DO_CHECKSUMS
				dmc->flashcache_stats.checksum_store++;
				flashcache_store_checksum(job);
				/* 
				 * We need to update the metadata on a DIRTY->DIRTY as well 
				 * since we save the checksums.
				 */
				flashcache_md_write(job);
				return;
#else
				/* Only do cache metadata update on a non-DIRTY->DIRTY transition */
				if ((cacheblk->cache_state & DIRTY) == 0) {
					flashcache_md_write(job);
					return;
				}
#endif
			} else { /* cache_mode == WRITE_THROUGH */
				/* Writs to both disk and cache completed */
				VERIFY(dmc->cache_mode == FLASHCACHE_WRITE_THROUGH);
#ifdef FLASHCACHE_DO_CHECKSUMS
				flashcache_store_checksum(job);
				job->dmc->flashcache_stats.checksum_store++;
#endif
			}
		} else {
			dmc->flashcache_errors.ssd_write_errors++;
			if (dmc->cache_mode == FLASHCACHE_WRITE_THROUGH)
				/* 
				 * We don't know if the IO failed because of a ssd write
				 * error or a disk write error. Bump up both.
				 * XXX - TO DO. We could check the error bits and allow
				 * the IO to succeed as long as the disk write suceeded.
				 * and invalidate the cache block.
				 */
			        disk_error = -EIO;
				dmc->flashcache_errors.disk_write_errors++;
		}
		break;
	}
        /*
         * If we get an error in write through || write around modes,
         * we try the disk directly, after invalidating the cached block.
         * see flashcache_do_pending_error().
         * XXX - We can do the same for writeback as well. But that is more
         * work. (a) we cannot fall back to disk when a ssd read of a dirty
         * cacheblock fails (b) we'd need to handle ssd metadata write
	 * failures as well and fall back to disk in those cases as well.
	 * 
	 * We track disk errors separately. If we get a disk error (in 
	 * writethru or writearound modes) end the IO right here.
         */
	if (likely(error == 0) || 
	    (dmc->cache_mode == FLASHCACHE_WRITE_BACK) ||
	    disk_error != 0) {
		flashcache_bio_endio(bio, error, dmc, &job->io_start_time);
		job->bio = NULL;
	}
	/* 
	 * The INPROG flag is still set. We cannot turn that off until all the pending requests
	 * processed. We need to loop the pending requests back to a workqueue. We have the job,
	 * add it to the pending req queue.
	 */
	spin_lock_irqsave(&cache_set->set_spin_lock, flags);
	if (unlikely(error || cacheblk->nr_queued > 0)) {
		spin_unlock_irqrestore(&cache_set->set_spin_lock, flags);
		push_pending(job);
		schedule_work(&_kcached_wq);
	} else {
		cacheblk->cache_state &= ~BLOCK_IO_INPROG;
		spin_unlock_irqrestore(&cache_set->set_spin_lock, flags);
		flashcache_free_cache_job(job);
		if (atomic_dec_and_test(&dmc->nr_jobs))
			wake_up(&dmc->destroyq);
	}
}

void
flashcache_free_pending_jobs(struct cache_c *dmc, struct cacheblock *cacheblk, 
			     int error)
{
	struct pending_job *pending_job, *freelist = NULL;
	int index = cacheblk - &dmc->cache[0];
	struct cache_set *cache_set = &dmc->cache_sets[index / dmc->assoc];

	VERIFY(spin_is_locked(&cache_set->set_spin_lock));
	freelist = flashcache_deq_pending(dmc, index);
	while (freelist != NULL) {
		pending_job = freelist;
		freelist = pending_job->next;
		VERIFY(cacheblk->nr_queued > 0);
		cacheblk->nr_queued--;
		flashcache_bio_endio(pending_job->bio, error, dmc, NULL);
		flashcache_free_pending_job(pending_job);
	}
	VERIFY(cacheblk->nr_queued == 0);
}

/* 
 * Common error handling for everything.
 * 1) If the block isn't dirty, invalidate it.
 * 2) De-link all pending IOs that totally or partly overlap this block.
 * 3) If it was an SSD error (bio != NULL), issue the invalidated block IO and other de-linked pending IOs uncached to disk. 
 * 4) Free the job.
 */
static void
flashcache_do_pending_error(struct kcached_job *job)
{
	struct cache_c *dmc = job->dmc;
	struct cacheblock *cacheblk = &dmc->cache[job->index];
	struct bio *bio = job->bio;
	int error = job->error;
	struct pending_job *pjob_list = NULL, *pjob = NULL;
	struct cache_set *cache_set = &dmc->cache_sets[job->index / dmc->assoc];

	if (!dmc->bypass_cache) {
		DMERR("flashcache_do_pending_error: error %d block %lu action %d", 
		      job->error, job->job_io_regions.disk.sector, job->action);
	}
	spin_lock_irq(&cache_set->set_spin_lock);
	VERIFY(cacheblk->cache_state & VALID);
	/* Invalidate block if possible */
	if ((cacheblk->cache_state & DIRTY) == 0) {
		atomic_dec(&dmc->cached_blocks);
		dmc->flashcache_stats.pending_inval++;
		flashcache_hash_remove(dmc, job->index);
		cacheblk->cache_state &= ~VALID;
		cacheblk->cache_state |= INVALID;
	} else
		VERIFY(dmc->cache_mode == FLASHCACHE_WRITE_BACK);
	cacheblk->cache_state &= ~(BLOCK_IO_INPROG);
	if ((cacheblk->cache_state & DIRTY) == 0)
		flashcache_invalid_insert(dmc, job->index);
	/*
	 * In case of an error in writethrough or writearound modes, if there
	 * are pending jobs, de-link them from the cacheblock so we can issue disk 
	 * IOs below.
	 */
	if (bio != NULL) {
		VERIFY(dmc->cache_mode != FLASHCACHE_WRITE_BACK);
		pjob_list = flashcache_deq_pending(dmc, cacheblk - &dmc->cache[0]);
		for (pjob = pjob_list ; pjob != NULL ; pjob = pjob->next) {
			VERIFY(cacheblk->nr_queued > 0);
			cacheblk->nr_queued--;
		}
		VERIFY(cacheblk->nr_queued == 0);
	} else
		flashcache_free_pending_jobs(dmc, cacheblk, job->error);
	spin_unlock_irq(&cache_set->set_spin_lock);
	if (bio != NULL) {
		/*
		 * Cache (read/write) error in write through or write around
		 * mode. Issue the IO directly to disk. We've already invalidated
		 * the cache block above.
		 */
		if (!dmc->bypass_cache)  /* suppress massive console output */
			DMERR("flashcache_do_pending_error: Re-launching errored IO"
			      "to disk, after io error %d block %lu",
			      error, bio->bi_sector);
		flashcache_start_uncached_io(dmc, bio);
		while (pjob_list != NULL) {
			pjob = pjob_list;
			pjob_list = pjob->next;
			flashcache_start_uncached_io(dmc, pjob->bio);
			flashcache_free_pending_job(pjob);
		}
	}
	flashcache_free_cache_job(job);
	if (atomic_dec_and_test(&dmc->nr_jobs))
		wake_up(&dmc->destroyq);
}

static void
flashcache_do_pending_noerror(struct kcached_job *job)
{
	struct cache_c *dmc = job->dmc;
	int index = job->index;
	struct pending_job *pending_job, *freelist;
	int queued;
	struct cacheblock *cacheblk = &dmc->cache[index];
 	struct cache_set *cache_set = &dmc->cache_sets[index / dmc->assoc];

 	spin_lock_irq(&cache_set->set_spin_lock);
	if (cacheblk->cache_state & DIRTY) {
		VERIFY(dmc->cache_mode == FLASHCACHE_WRITE_BACK);
		cacheblk->cache_state &= ~(BLOCK_IO_INPROG);
		cacheblk->cache_state |= DISKWRITEINPROG;
		flashcache_clear_fallow(dmc, index);
 		spin_unlock_irq(&cache_set->set_spin_lock);
		flashcache_dirty_writeback(dmc, index);
		goto out;
	}
	DPRINTK("flashcache_do_pending: Index %d %lx",
		index, cacheblk->cache_state);
	VERIFY(cacheblk->cache_state & VALID);
 	atomic_dec(&dmc->cached_blocks);
	dmc->flashcache_stats.pending_inval++;
	flashcache_hash_remove(dmc, index);
	cacheblk->cache_state &= ~VALID;
	cacheblk->cache_state |= INVALID;
	/*
	 * The block is in limbo right now. It is not VALID, but the IO_INPROG
	 * bits are set, so it cannot be reused. So it is safe to drop the
	 * cache set lock here.
	 */
	spin_unlock_irq(&cache_set->set_spin_lock);
	freelist = flashcache_deq_pending(dmc, index);
	while (freelist != NULL) {
		pending_job = freelist;
		freelist = pending_job->next;
		flashcache_setlocks_multiget(dmc, pending_job->bio);
		VERIFY(!(cacheblk->cache_state & DIRTY));
		VERIFY(cacheblk->nr_queued > 0);
		cacheblk->nr_queued--;
		if (pending_job->action == INVALIDATE) {
			DPRINTK("flashcache_do_pending: INVALIDATE  %llu",
				next_job->bio->bi_sector);
			VERIFY(pending_job->bio != NULL);
			queued = flashcache_inval_blocks(dmc, pending_job->bio);
			if (queued) {
				flashcache_setlocks_multidrop(dmc, pending_job->bio);
				if (unlikely(queued < 0)) {
					/*
					 * Memory allocation failure inside inval_blocks.
					 * Fail this io.
					 */
					flashcache_bio_endio(pending_job->bio, -EIO, dmc, NULL);
				}
				flashcache_free_pending_job(pending_job);
				continue;
			}
		}
		flashcache_setlocks_multidrop(dmc, pending_job->bio);
		DPRINTK("flashcache_do_pending: Sending down IO %llu",
			pending_job->bio->bi_sector);
		/* Start uncached IO */
		flashcache_start_uncached_io(dmc, pending_job->bio);
		flashcache_free_pending_job(pending_job);
	}
 	spin_lock_irq(&cache_set->set_spin_lock);
	VERIFY(cacheblk->nr_queued == 0);
	cacheblk->cache_state &= ~(BLOCK_IO_INPROG);
	flashcache_invalid_insert(dmc, index);
 	spin_unlock_irq(&cache_set->set_spin_lock);
out:
	flashcache_free_cache_job(job);
	if (atomic_dec_and_test(&dmc->nr_jobs))
		wake_up(&dmc->destroyq);
}

void
flashcache_do_pending(struct kcached_job *job)
{
	if (job->error)
		flashcache_do_pending_error(job);
	else
		flashcache_do_pending_noerror(job);
}

void
flashcache_do_io(struct kcached_job *job)
{
	struct bio *bio = job->bio;
	int r = 0;
	
	VERIFY(job->action == READFILL);
	VERIFY(job->action == READFILL);
#ifdef FLASHCACHE_DO_CHECKSUMS
	flashcache_store_checksum(job);
	job->dmc->flashcache_stats.checksum_store++;
#endif
	/* Write to cache device */
	job->dmc->flashcache_stats.ssd_writes++;
	r = dm_io_async_bvec(1, &job->job_io_regions.cache, WRITE, bio,
			     flashcache_io_callback, job);
	VERIFY(r == 0);
	/* In our case, dm_io_async_bvec() must always return 0 */
}

/*
 * Map a block from the source device to a block in the cache device.
 */
unsigned long 
hash_block(struct cache_c *dmc, sector_t dbn)
{
	unsigned long set_number, value;
        int num_cache_sets = dmc->size >> dmc->assoc_shift;

	/*
	 * Starting in Flashcache SSD Version 3 :
	 * We map a sequential cluster of disk_assoc blocks onto a given set.
	 * But each disk_assoc cluster can be randomly placed in any set.
	 * But if we are running on an older on-ssd cache, we preserve old
	 * behavior.
	 */
	if (dmc->on_ssd_version < 3 || dmc->disk_assoc == 0) {
		value = (unsigned long)
			(dbn >> (dmc->block_shift + dmc->assoc_shift));
	} else {
		/* Shift out the low disk_assoc bits */
		value = (unsigned long) (dbn >> dmc->disk_assoc_shift);
		/* Then place it in a random set */
		value = jhash_1word(value, 0xbeef);
	}
	set_number = value % num_cache_sets;
	DPRINTK("Hash: %llu(%lu)->%lu", dbn, value, set_number);
	return set_number;
}

static void
find_valid_dbn(struct cache_c *dmc, sector_t dbn, 
	       int start_index, int *index)
{
	*index = flashcache_hash_lookup(dmc, start_index / dmc->assoc, dbn);
	if (*index == -1)
		return;
	if (dmc->sysctl_reclaim_policy == FLASHCACHE_LRU &&
	    ((dmc->cache[*index].cache_state & BLOCK_IO_INPROG) == 0))
		flashcache_lru_accessed(dmc, *index);
	/* 
	 * If the block was DIRTY and earmarked for cleaning because it was old, make 
	 * the block young again.
	 */
	flashcache_clear_fallow(dmc, *index);
}

static int
find_invalid_dbn(struct cache_c *dmc, int set)
{
	int index = flashcache_invalid_get(dmc, set);

	if (index != -1) {
		if (dmc->sysctl_reclaim_policy == FLASHCACHE_LRU)
			flashcache_lru_accessed(dmc, index);
		VERIFY((dmc->cache[index].cache_state & FALLOW_DOCLEAN) == 0);
	}
	return index;
}

/* Search for a slot that we can reclaim */
static void
find_reclaim_dbn(struct cache_c *dmc, int start_index, int *index)
{
	if (dmc->sysctl_reclaim_policy == FLASHCACHE_FIFO)
		flashcache_reclaim_fifo_get_old_block(dmc, start_index, index);
	else /* flashcache_reclaim_policy == FLASHCACHE_LRU */
		flashcache_reclaim_lru_get_old_block(dmc, start_index, index);
}

/* 
 * dbn is the starting sector, io_size is the number of sectors.
 */
static int 
flashcache_lookup(struct cache_c *dmc, struct bio *bio, int *index)
{
	sector_t dbn = bio->bi_sector;
#if DMC_DEBUG
	int io_size = to_sector(bio->bi_size);
#endif
	unsigned long set_number = hash_block(dmc, dbn);
	int invalid, oldest_clean = -1;
	int start_index;

	start_index = dmc->assoc * set_number;
	DPRINTK("Cache lookup : dbn %llu(%lu), set = %d",
		dbn, io_size, set_number);
	find_valid_dbn(dmc, dbn, start_index, index);
	if (*index >= 0) {
		DPRINTK("Cache lookup HIT: Block %llu(%lu): VALID index %d",
			     dbn, io_size, *index);
		/* We found the exact range of blocks we are looking for */
		return VALID;
	}
	invalid = find_invalid_dbn(dmc, set_number);
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
		DPRINTK("Cache lookup MISS (INVALID): dbn %llu(%lu), set = %d, index = %d, start_index = %d",
			     dbn, io_size, set_number, invalid, start_index);
		*index = invalid;
	} else if (oldest_clean != -1) {
		DPRINTK("Cache lookup MISS (VALID): dbn %llu(%lu), set = %d, index = %d, start_index = %d",
			     dbn, io_size, set_number, oldest_clean, start_index);
		*index = oldest_clean;
	} else {
		DPRINTK_LITE("Cache read lookup MISS (NOROOM): dbn %llu(%lu), set = %d",
			dbn, io_size, set_number);
	}
	if (*index < (start_index + dmc->assoc))
		return INVALID;
	else {
		dmc->flashcache_stats.noroom++;
		return -1;
	}
}

/*
 * Cache Metadata Update functions 
 */
void 
flashcache_md_write_callback(unsigned long error, void *context)
{
	struct kcached_job *job = (struct kcached_job *)context;

	if (unlikely(error))
		job->error = -EIO;
	else
		job->error = 0;
	push_md_complete(job);
	schedule_work(&_kcached_wq);
}

static int
flashcache_alloc_md_sector(struct kcached_job *job)
{
	struct page *page = NULL;
	struct cache_c *dmc = job->dmc;	
	unsigned long addr = 0;
	
	if (likely((dmc->sysctl_error_inject & MD_ALLOC_SECTOR_ERROR) == 0)) {
		/* Get physically consecutive pages */
		addr = __get_free_pages(GFP_NOIO, get_order(MD_BLOCK_BYTES(job->dmc)));
		if (addr)
			page = virt_to_page(addr);
	} else
		dmc->sysctl_error_inject &= ~MD_ALLOC_SECTOR_ERROR;
	if (unlikely(page == NULL)) {
		job->dmc->flashcache_errors.memory_alloc_errors++;
		return -ENOMEM;
	} else {
		job->pl_base[0].page = page;
		job->pl_base[0].next = NULL;	
		job->md_block = (struct flash_cacheblock *)addr;
		return 0;
	}
}

static void
flashcache_free_md_sector(struct kcached_job *job)
{
	if (job->pl_base[0].page != NULL)
		__free_pages(job->pl_base[0].page, get_order(MD_BLOCK_BYTES(job->dmc)));
	job->pl_base[0].page = NULL;
}

void
flashcache_md_write_kickoff(struct kcached_job *job)
{
	struct cache_c *dmc = job->dmc;	
	struct flash_cacheblock *md_block;
	int md_block_ix;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	struct io_region where;
#else
	struct dm_io_region where;
#endif
	int i;
	struct cache_md_block_head *md_block_head;
	struct kcached_job *orig_job = job;
	struct cache_set *cache_set = &dmc->cache_sets[job->index / dmc->assoc];

	if (flashcache_alloc_md_sector(job)) {
		DMERR("flashcache: %d: Cache metadata write failed, cannot alloc page ! block %lu", 
		      job->action, job->job_io_regions.disk.sector);
		flashcache_md_write_callback(-EIO, job);
		return;
	}
	/*
	 * Transfer whatever is on the pending queue to the md_io_inprog queue.
	 */
	md_block_head = &dmc->md_blocks_buf[INDEX_TO_MD_BLOCK(dmc, job->index)];
	spin_lock_irq(&cache_set->set_spin_lock);
	spin_lock(&md_block_head->md_block_lock);
	md_block_head->md_io_inprog = md_block_head->queued_updates;
	md_block_head->queued_updates = NULL;
	md_block = job->md_block;
	md_block_ix = INDEX_TO_MD_BLOCK(dmc, job->index) * MD_SLOTS_PER_BLOCK(dmc);
	/* First copy out the entire md block */
	for (i = 0 ; 
	     i < MD_SLOTS_PER_BLOCK(dmc) && md_block_ix < dmc->size ; 
	     i++, md_block_ix++) {
		md_block[i].dbn = dmc->cache[md_block_ix].dbn;
#ifdef FLASHCACHE_DO_CHECKSUMS
		md_block[i].checksum = dmc->cache[md_block_ix].checksum;
#endif
		md_block[i].cache_state = 
			dmc->cache[md_block_ix].cache_state & (VALID | INVALID | DIRTY);
	}
	/* Then set/clear the DIRTY bit for the "current" index */
	if (job->action == WRITECACHE) {
		/* DIRTY the cache block */
		md_block[INDEX_TO_MD_BLOCK_OFFSET(dmc, job->index)].cache_state = 
			(VALID | DIRTY);
	} else { /* job->action == WRITEDISK* */
		/* un-DIRTY the cache block */
		md_block[INDEX_TO_MD_BLOCK_OFFSET(dmc, job->index)].cache_state = VALID;
	}

	for (job = md_block_head->md_io_inprog ; 
	     job != NULL ;
	     job = job->next) {
		dmc->flashcache_stats.md_write_batch++;
		if (job->action == WRITECACHE) {
			/* DIRTY the cache block */
			md_block[INDEX_TO_MD_BLOCK_OFFSET(dmc, job->index)].cache_state = 
				(VALID | DIRTY);
		} else { /* job->action == WRITEDISK* */
			/* un-DIRTY the cache block */
			md_block[INDEX_TO_MD_BLOCK_OFFSET(dmc, job->index)].cache_state = VALID;
		}
	}
	spin_unlock(&md_block_head->md_block_lock);
	spin_unlock_irq(&cache_set->set_spin_lock);
	where.bdev = dmc->cache_dev->bdev;
	where.count = MD_SECTORS_PER_BLOCK(dmc);
	where.sector = (1 + INDEX_TO_MD_BLOCK(dmc, orig_job->index)) * MD_SECTORS_PER_BLOCK(dmc);
	dmc->flashcache_stats.ssd_writes++;
	dmc->flashcache_stats.md_ssd_writes++;
	dm_io_async_bvec_pl(1, &where, WRITE,
			    &orig_job->pl_base[0],
			    flashcache_md_write_callback, orig_job);
}

void
flashcache_md_write_done(struct kcached_job *job)
{
	struct cache_c *dmc = job->dmc;
	struct cache_md_block_head *md_block_head;
	int index, orig_index = job->index;
	struct kcached_job *job_list;
	int error = job->error;
	struct kcached_job *next;
	struct cacheblock *cacheblk;
	int set;
	struct cache_set *cache_set;
		
	VERIFY(!in_interrupt());
	VERIFY(job->action == WRITEDISK || job->action == WRITECACHE || 
	       job->action == WRITEDISK_SYNC);
	flashcache_free_md_sector(job);
	job->md_block = NULL;
	md_block_head = &dmc->md_blocks_buf[INDEX_TO_MD_BLOCK(dmc, job->index)];
	job_list = job;
	spin_lock_irq(&md_block_head->md_block_lock);
	job->next = md_block_head->md_io_inprog;
	md_block_head->md_io_inprog = NULL;
	spin_unlock_irq(&md_block_head->md_block_lock);
	for (job = job_list ; job != NULL ; job = next) {
		next = job->next;
		job->error = error;
		index = job->index;
		set = index / dmc->assoc;
		cache_set = &dmc->cache_sets[set];
		cacheblk = &dmc->cache[index];
		spin_lock_irq(&cache_set->set_spin_lock);
		if (job->action == WRITECACHE) {
			if (unlikely(dmc->sysctl_error_inject & WRITECACHE_MD_ERROR)) {
				job->error = -EIO;
				dmc->sysctl_error_inject &= ~WRITECACHE_MD_ERROR;
			}
			if (likely(job->error == 0)) {
				if ((cacheblk->cache_state & DIRTY) == 0) {
					cache_set->nr_dirty++;
					atomic_inc(&dmc->nr_dirty);
				}
				dmc->flashcache_stats.md_write_dirty++;
				cacheblk->cache_state |= DIRTY;
			} else
				dmc->flashcache_errors.ssd_write_errors++;
			flashcache_bio_endio(job->bio, job->error, dmc, &job->io_start_time);
			if (job->error || cacheblk->nr_queued > 0) {
				if (job->error) {
					DMERR("flashcache: WRITE: Cache metadata write failed ! error %d block %lu", 
					      job->error, cacheblk->dbn);
				}
				spin_unlock_irq(&cache_set->set_spin_lock);
				flashcache_do_pending(job);
			} else {
				cacheblk->cache_state &= ~BLOCK_IO_INPROG;
				spin_unlock_irq(&cache_set->set_spin_lock);
				flashcache_free_cache_job(job);
				if (atomic_dec_and_test(&dmc->nr_jobs))
					wake_up(&dmc->destroyq);
			}
		} else {
			int action = job->action;

			if (unlikely(dmc->sysctl_error_inject & WRITEDISK_MD_ERROR)) {
				job->error = -EIO;
				dmc->sysctl_error_inject &= ~WRITEDISK_MD_ERROR;
			}
			/*
			 * If we have an error on a WRITEDISK*, no choice but to preserve the 
			 * dirty block in cache. Fail any IOs for this block that occurred while
			 * the block was being cleaned.
			 */
			if (likely(job->error == 0)) {
				dmc->flashcache_stats.md_write_clean++;
				cacheblk->cache_state &= ~DIRTY;
				VERIFY(cache_set->nr_dirty > 0);
				VERIFY(atomic_read(&dmc->nr_dirty) > 0);
				cache_set->nr_dirty--;
				atomic_dec(&dmc->nr_dirty);
			} else 
				dmc->flashcache_errors.ssd_write_errors++;
			VERIFY(cache_set->clean_inprog > 0);
			VERIFY(atomic_read(&dmc->clean_inprog) > 0);
			cache_set->clean_inprog--;
			atomic_dec(&dmc->clean_inprog);
			if (job->error || cacheblk->nr_queued > 0) {
				if (job->error) {
					DMERR("flashcache: CLEAN: Cache metadata write failed ! error %d block %lu", 
					      job->error, cacheblk->dbn);
				}
				spin_unlock_irq(&cache_set->set_spin_lock);
				flashcache_do_pending(job);
			} else {
				cacheblk->cache_state &= ~BLOCK_IO_INPROG;
				spin_unlock_irq(&cache_set->set_spin_lock);
				flashcache_free_cache_job(job);
				if (atomic_dec_and_test(&dmc->nr_jobs))
					wake_up(&dmc->destroyq);
			}
			/* Kick off more cleanings */
			if (action == WRITEDISK)
				flashcache_clean_set(dmc, set, 0);
			else
				flashcache_sync_blocks(dmc);
			dmc->flashcache_stats.cleanings++;
			if (action == WRITEDISK_SYNC)
				flashcache_update_sync_progress(dmc);
		}
	}
	cache_set = &dmc->cache_sets[orig_index / dmc->assoc];
	spin_lock_irq(&cache_set->set_spin_lock);
	spin_lock(&md_block_head->md_block_lock);
	if (md_block_head->queued_updates != NULL) {
		/* peel off the first job from the pending queue and kick that off */
		job = md_block_head->queued_updates;
		md_block_head->queued_updates = job->next;
		spin_unlock(&md_block_head->md_block_lock);
		job->next = NULL;
		spin_unlock_irq(&cache_set->set_spin_lock);
		VERIFY(job->action == WRITEDISK || job->action == WRITECACHE ||
		       job->action == WRITEDISK_SYNC);
		flashcache_md_write_kickoff(job);
	} else {
		md_block_head->nr_in_prog = 0;
		spin_unlock(&md_block_head->md_block_lock);
		spin_unlock_irq(&cache_set->set_spin_lock);
	}
}

/* 
 * Kick off a cache metadata update (called from workqueue).
 * Cache metadata update IOs to a given metadata sector are serialized using the 
 * nr_in_prog bit in the md sector bufhead.
 * If a metadata IO is already in progress, we queue up incoming metadata updates
 * on the pending_jobs list of the md sector bufhead. When kicking off an IO, we
 * cluster all these pending updates and do all of them as 1 flash write (that 
 * logic is in md_write_kickoff), where it switches out the entire pending_jobs
 * list and does all of those updates as 1 ssd write.
 */
void
flashcache_md_write(struct kcached_job *job)
{
	struct cache_c *dmc = job->dmc;
	struct cache_md_block_head *md_block_head;
	unsigned long flags;
	
	VERIFY(job->action == WRITEDISK || job->action == WRITECACHE || 
	       job->action == WRITEDISK_SYNC);
	md_block_head = &dmc->md_blocks_buf[INDEX_TO_MD_BLOCK(dmc, job->index)];
	spin_lock_irqsave(&md_block_head->md_block_lock, flags);
	/* If a write is in progress for this metadata sector, queue this update up */
	if (md_block_head->nr_in_prog != 0) {
		struct kcached_job **nodepp;
		
		/* A MD update is already in progress, queue this one up for later */
		nodepp = &md_block_head->queued_updates;
		while (*nodepp != NULL)
			nodepp = &((*nodepp)->next);
		job->next = NULL;
		*nodepp = job;
		spin_unlock_irqrestore(&md_block_head->md_block_lock, flags);
	} else {
		md_block_head->nr_in_prog = 1;
		spin_unlock_irqrestore(&md_block_head->md_block_lock, flags);
		/*
		 * Always push to a worker thread. If the driver has
		 * a completion thread, we could end up deadlocking even
		 * if the context would be safe enough to write from.
		 * This could be executed from the context of an IO 
		 * completion thread. Kicking off the write from that
		 * context could result in the IO completion thread 
		 * blocking (eg on memory allocation). That can easily
		 * deadlock.
		 */
		push_md_io(job);
		schedule_work(&_kcached_wq);
	}
}

static void 
flashcache_kcopyd_callback(int read_err, unsigned int write_err, void *context)
{
	struct kcached_job *job = (struct kcached_job *)context;
	struct cache_c *dmc = job->dmc;
	int index = job->index;
	int set = index / dmc->assoc;
	struct cache_set *cache_set = &dmc->cache_sets[set];

	VERIFY(!in_interrupt());
	DPRINTK("kcopyd_callback: Index %d", index);
	VERIFY(job->bio == NULL);
	spin_lock_irq(&cache_set->set_spin_lock);
	VERIFY(dmc->cache[index].cache_state & (DISKWRITEINPROG | VALID | DIRTY));
	if (unlikely(dmc->sysctl_error_inject & KCOPYD_CALLBACK_ERROR)) {
		read_err = -EIO;
		dmc->sysctl_error_inject &= ~KCOPYD_CALLBACK_ERROR;
	}
	if (likely(read_err == 0 && write_err == 0)) {
		spin_unlock_irq(&cache_set->set_spin_lock);
		flashcache_md_write(job);
	} else {
		if (read_err)
			read_err = -EIO;
		if (write_err)
			write_err = -EIO;
		/* Disk write failed. We can not purge this block from flash */
		DMERR("flashcache: Disk writeback failed ! read error %d write error %d block %lu", 
		      -read_err, -write_err, job->job_io_regions.disk.sector);
		VERIFY(cache_set->clean_inprog > 0);
		cache_set->clean_inprog--;
		VERIFY(atomic_read(&dmc->clean_inprog) > 0);
		atomic_dec(&dmc->clean_inprog);
		spin_unlock_irq(&cache_set->set_spin_lock);
		/* Set the error in the job and let do_pending() handle the error */
		if (read_err) {
			dmc->flashcache_errors.ssd_read_errors++;
			job->error = read_err;
		} else {
			dmc->flashcache_errors.disk_write_errors++;
			job->error = write_err;
		}
		flashcache_do_pending(job);
		flashcache_clean_set(dmc, set, 0); /* Kick off more cleanings */
		dmc->flashcache_stats.cleanings++;
	}
}

static void
flashcache_dirty_writeback(struct cache_c *dmc, int index)
{
	struct kcached_job *job;
	struct cacheblock *cacheblk = &dmc->cache[index];
	int device_removal = 0;
	int set = index / dmc->assoc;
	struct cache_set *cache_set = &dmc->cache_sets[set];
	
	DPRINTK("flashcache_dirty_writeback: Index %d", index);
	spin_lock_irq(&cache_set->set_spin_lock);
	VERIFY((cacheblk->cache_state & BLOCK_IO_INPROG) == DISKWRITEINPROG);
	VERIFY(cacheblk->cache_state & DIRTY);
	cache_set->clean_inprog++;
	atomic_inc(&dmc->clean_inprog);
	spin_unlock_irq(&cache_set->set_spin_lock);
	job = new_kcached_job(dmc, NULL, index);
	if (unlikely(dmc->sysctl_error_inject & DIRTY_WRITEBACK_JOB_ALLOC_FAIL)) {
		if (job)
			flashcache_free_cache_job(job);
		job = NULL;
		dmc->sysctl_error_inject &= ~DIRTY_WRITEBACK_JOB_ALLOC_FAIL;
	}
	/*
	 * If the device is being removed, do not kick off any more cleanings.
	 */
	if (unlikely(atomic_read(&dmc->remove_in_prog))) {
		DMERR("flashcache: Dirty Writeback (for set cleaning) aborted for device removal, block %lu", 
		      cacheblk->dbn);
		if (job)
			flashcache_free_cache_job(job);
		job = NULL;
		device_removal = 1;
	}
	if (unlikely(job == NULL)) {
		spin_lock_irq(&cache_set->set_spin_lock);
		cache_set->clean_inprog--;
		atomic_dec(&dmc->clean_inprog);
		flashcache_free_pending_jobs(dmc, cacheblk, -EIO);
		cacheblk->cache_state &= ~(BLOCK_IO_INPROG);
		spin_unlock_irq(&cache_set->set_spin_lock);
		if (device_removal == 0)
			DMERR("flashcache: Dirty Writeback (for set cleaning) failed ! Can't allocate memory, block %lu", 
			      cacheblk->dbn);
	} else {
		job->bio = NULL;
		job->action = WRITEDISK;
		atomic_inc(&dmc->nr_jobs);
		dmc->flashcache_stats.ssd_reads++;
		dmc->flashcache_stats.disk_writes++;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
		kcopyd_copy(flashcache_kcp_client, &job->job_io_regions.cache, 1, &job->job_io_regions.disk, 0, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
			    flashcache_kcopyd_callback, 
#else
			    (kcopyd_notify_fn) flashcache_kcopyd_callback, 
#endif
			    job);
#else
		dm_kcopyd_copy(flashcache_kcp_client, &job->job_io_regions.cache, 1, &job->job_io_regions.disk, 0, 
			       (dm_kcopyd_notify_fn) flashcache_kcopyd_callback, 
			       (void *)job);
#endif
	}
}

/*
 * This function encodes the background disk cleaning logic.
 * Background disk cleaning is triggered for 2 reasons.
 A) Dirty blocks are lying fallow in the set, making them good 
    candidates for being cleaned.
 B) This set has dirty blocks over the configured threshold 
    for a set.
 * (A) takes precedence over (B). Fallow dirty blocks are cleaned
 * first.
 * The cleaning of disk blocks is subject to the write limits per
 * set and across the cache, which this function enforces.
 *
 * 1) Select the n blocks that we want to clean (choosing whatever policy), 
 *    sort them.
 * 2) Then sweep the entire set looking for other DIRTY blocks that can be 
 *    tacked onto any of these blocks to form larger contigous writes. 
 *    The idea here is that if you are going to do a write anyway, then we 
 *    might as well opportunistically write out any contigous blocks for 
 *    free.
 */

/* Are we under the limits for disk cleaning ? */
static inline int
flashcache_can_clean(struct cache_c *dmc, 
		     struct cache_set *cache_set,
		     int nr_writes)
{
	return ((cache_set->clean_inprog + nr_writes) < dmc->max_clean_ios_set &&
		(nr_writes + atomic_read(&dmc->clean_inprog)) < dmc->max_clean_ios_total);
}

void
flashcache_clean_set(struct cache_c *dmc, int set, int force_clean_blocks)
{
	int threshold_clean = 0;
	struct dbn_index_pair *writes_list = NULL;
	struct dbn_index_pair *set_dirty_list = NULL;
	int nr_writes = 0, i;
	int start_index = set * dmc->assoc; 
	int end_index = start_index + dmc->assoc;
	struct cache_set *cache_set = &dmc->cache_sets[set];
	struct cacheblock *cacheblk;
	int do_delayed_clean = 0;
	int scanned = 0;

	if (dmc->cache_mode != FLASHCACHE_WRITE_BACK)
		return;
	if (dmc->sysctl_reclaim_policy == FLASHCACHE_FIFO)
		/* 
		 * We only do force cleaning on a cache miss if reclaim policy
		 * is LRU.
		 */
		force_clean_blocks = 0;
	/* 
	 * If a removal of this device is in progress, don't kick off 
	 * any more cleanings. This isn't sufficient though. We still need to
	 * stop cleanings inside flashcache_dirty_writeback() because we could
	 * have started a device remove after tested this here.
	 */
	if (atomic_read(&dmc->remove_in_prog))
		return;
	if (flashcache_diskclean_alloc(dmc, &writes_list, &set_dirty_list)) {
		dmc->flashcache_errors.memory_alloc_errors++;
		return;
	}
	spin_lock_irq(&cache_set->set_spin_lock);
	/* 
	 * Before we try to clean any blocks, check the last time the fallow block
	 * detection was done. If it has been more than "fallow_delay" seconds, make 
	 * a sweep through the set to detect (mark) fallow blocks.
	 */
	if (dmc->sysctl_fallow_delay && time_after(jiffies, cache_set->fallow_tstamp)) {
		for (i = start_index ; i < end_index ; i++)
			flashcache_detect_fallow(dmc, i);
		cache_set->fallow_tstamp = jiffies + dmc->sysctl_fallow_delay * HZ;
	}
	/* If there are any dirty fallow blocks, clean them first */
	for (i = start_index ; 
	     (dmc->sysctl_fallow_delay > 0 &&
	      cache_set->dirty_fallow > 0 &&
	      time_after(jiffies, cache_set->fallow_next_cleaning) &&
	      i < end_index) ; 
	     i++) {
		cacheblk = &dmc->cache[i];
		if (!(cacheblk->cache_state & DIRTY_FALLOW_2))
			continue;
		if (!flashcache_can_clean(dmc, cache_set, nr_writes)) {
			/*
			 * There are fallow blocks that need cleaning, but we 
			 * can't clean them this pass, schedule delayed cleaning 
			 * later.
			 */
			do_delayed_clean = 1;
			goto out;
		}
		VERIFY(cacheblk->cache_state & DIRTY);
		VERIFY((cacheblk->cache_state & BLOCK_IO_INPROG) == 0);
		cacheblk->cache_state |= DISKWRITEINPROG;
		flashcache_clear_fallow(dmc, i);
		writes_list[nr_writes].dbn = cacheblk->dbn;
		writes_list[nr_writes].index = i;
		dmc->flashcache_stats.fallow_cleanings++;
		nr_writes++;
	}
	if (nr_writes > 0)
		cache_set->fallow_next_cleaning = jiffies + HZ / dmc->sysctl_fallow_clean_speed;
	/*
	 * In the miss path, we try to clean at least one block so the cache set does not
	 * fill up with dirty fallow blocks.
	 */
	if (force_clean_blocks == 0) {
		if (cache_set->nr_dirty < dmc->dirty_thresh_set ||
		    !flashcache_can_clean(dmc, cache_set, nr_writes))
			goto out;
		/*
		 * We picked up all the dirty fallow blocks we can. We can still clean more to
		 * remain under the dirty threshold. Clean some more blocks.
		 */
		threshold_clean = cache_set->nr_dirty - dmc->dirty_thresh_set;
	} else if (cache_set->nr_dirty > 0) {
		/* We want to clean at least 1 block - miss path */
		if (cache_set->nr_dirty > dmc->dirty_thresh_set) {
			/* We can definitely clean some based on thresholds */
			threshold_clean = cache_set->nr_dirty - dmc->dirty_thresh_set;
			force_clean_blocks = 0;
		} else if (nr_writes == 0) {
			/* XXX - Should be nr_writes < force_clean_blocks */
			dmc->flashcache_stats.force_clean_block++;
			threshold_clean = force_clean_blocks;
		}
	}
	if (dmc->sysctl_reclaim_policy == FLASHCACHE_FIFO) {
		i = cache_set->set_clean_next;
		DPRINTK("flashcache_clean_set: Set %d", set);
		while (scanned < dmc->assoc &&
		       flashcache_can_clean(dmc, cache_set, nr_writes) &&
		       nr_writes < threshold_clean) {
			cacheblk = &dmc->cache[i];
			if ((cacheblk->cache_state & (DIRTY | BLOCK_IO_INPROG)) == DIRTY) {
				cacheblk->cache_state |= DISKWRITEINPROG;
				flashcache_clear_fallow(dmc, i);
				writes_list[nr_writes].dbn = cacheblk->dbn;
				writes_list[nr_writes].index = i;
				nr_writes++;
			}
			scanned++;
			i++;
			if (i == end_index)
				i = start_index;
		}
		cache_set->set_clean_next = i;
	} else { /* reclaim_policy == FLASHCACHE_LRU */
		int lru_rel_index;
		int iter;

		for (iter = 0 ; iter < 2 ; iter++) {
			if (iter == 0)
				lru_rel_index = cache_set->warmlist_lru_head;
			else
				lru_rel_index = cache_set->hotlist_lru_head;
			while (lru_rel_index != FLASHCACHE_NULL &&
			       flashcache_can_clean(dmc, cache_set, nr_writes) &&
			       nr_writes < threshold_clean) {
				cacheblk = &dmc->cache[lru_rel_index + start_index];
				if ((cacheblk->cache_state & (DIRTY | BLOCK_IO_INPROG)) == DIRTY) {
					cacheblk->cache_state |= DISKWRITEINPROG;
					flashcache_clear_fallow(dmc, lru_rel_index + start_index);
					writes_list[nr_writes].dbn = cacheblk->dbn;
					writes_list[nr_writes].index = cacheblk - &dmc->cache[0];
					nr_writes++;
				}
				scanned++;
				/*
				 * If we are forced to clean on replacement, only clean blocks at
				 * the tail end of the LRU list !
				 */
				if (force_clean_blocks > 0 && scanned == force_clean_blocks)
					goto out;
				lru_rel_index = cacheblk->lru_next;
			}
		}
	}
out:
	if (nr_writes > 0) {
		flashcache_merge_writes(dmc, writes_list, set_dirty_list, &nr_writes, set);
		dmc->flashcache_stats.clean_set_ios += nr_writes;
		if (nr_writes < FLASHCACHE_WRITE_CLUST_HIST_SIZE)
			dmc->write_clust_hist[nr_writes]++;
		else
			dmc->write_clust_hist_ovf++;
		spin_unlock_irq(&cache_set->set_spin_lock);
		/* 
		 * XXX - There are some subtle bugs in the flashcache_kcopy code 
		 * (leaked copy jobs). Until we fix those, revert to the original
		 * logic of using the kernel kcopyd code. If you enable 
		 * flashcache_kcopy, enable the code in flashcache_kcopy_init().
		 */
#if 1
		for (i = 0 ; i < nr_writes ; i++)
			flashcache_dirty_writeback(dmc, writes_list[i].index);
#else
		flashcache_copy_data(dmc, cache_set, nr_writes, writes_list);
#endif
	} else {
		if (cache_set->nr_dirty > dmc->dirty_thresh_set)
			do_delayed_clean = 1;
		spin_unlock_irq(&cache_set->set_spin_lock);
		if (do_delayed_clean)
			schedule_delayed_work(&dmc->delayed_clean, 1*HZ);
	}
	flashcache_diskclean_free(dmc, writes_list, set_dirty_list);
}

static void
flashcache_read_hit(struct cache_c *dmc, struct bio* bio, int index)
{
	struct cacheblock *cacheblk;
	struct pending_job *pjob;
	int set = index / dmc->assoc;

	cacheblk = &dmc->cache[index];
	/* If block is busy, queue IO pending completion of in-progress IO */
	if (!(cacheblk->cache_state & BLOCK_IO_INPROG) && (cacheblk->nr_queued == 0)) {
		struct kcached_job *job;
			
		cacheblk->cache_state |= CACHEREADINPROG;
		dmc->flashcache_stats.read_hits++;
		flashcache_setlocks_multidrop(dmc, bio);
		DPRINTK("Cache read: Block %llu(%lu), index = %d:%s",
			bio->bi_sector, bio->bi_size, index, "CACHE HIT");
		job = new_kcached_job(dmc, bio, index);
		if (unlikely(dmc->sysctl_error_inject & READ_HIT_JOB_ALLOC_FAIL)) {
			if (job)
				flashcache_free_cache_job(job);
			job = NULL;
			dmc->sysctl_error_inject &= ~READ_HIT_JOB_ALLOC_FAIL;
		}
		if (unlikely(job == NULL)) {
			/* 
			 * We have a read hit, and can't allocate a job.
			 * Since we dropped the spinlock, we have to drain any 
			 * pending jobs.
			 */
			DMERR("flashcache: Read (hit) failed ! Can't allocate memory for cache IO, block %lu", 
			      cacheblk->dbn);
			flashcache_bio_endio(bio, -EIO, dmc, NULL);
			spin_lock_irq(&dmc->cache_sets[set].set_spin_lock);
			flashcache_free_pending_jobs(dmc, cacheblk, -EIO);
			cacheblk->cache_state &= ~(BLOCK_IO_INPROG);
			spin_unlock_irq(&dmc->cache_sets[set].set_spin_lock);
		} else {
			job->action = READCACHE; /* Fetch data from cache */
			atomic_inc(&dmc->nr_jobs);
			dmc->flashcache_stats.ssd_reads++;
			dm_io_async_bvec(1, &job->job_io_regions.cache, READ,
					 bio,
					 flashcache_io_callback, job);
		}
	} else {
		pjob = flashcache_alloc_pending_job(dmc);
		if (unlikely(dmc->sysctl_error_inject & READ_HIT_PENDING_JOB_ALLOC_FAIL)) {
			if (pjob) {
				flashcache_free_pending_job(pjob);
				pjob = NULL;
			}
			dmc->sysctl_error_inject &= ~READ_HIT_PENDING_JOB_ALLOC_FAIL;
		}
		if (pjob == NULL)
			flashcache_bio_endio(bio, -EIO, dmc, NULL);
		else
			flashcache_enq_pending(dmc, bio, index, READCACHE, pjob);
		flashcache_setlocks_multidrop(dmc, bio);
	}
}

static void
flashcache_read_miss(struct cache_c *dmc, struct bio* bio,
		     int index)
{
	struct kcached_job *job;
	struct cacheblock *cacheblk = &dmc->cache[index];
	int set = index / dmc->assoc;
	struct cache_set *cache_set = &dmc->cache_sets[set];

	job = new_kcached_job(dmc, bio, index);
	if (unlikely(dmc->sysctl_error_inject & READ_MISS_JOB_ALLOC_FAIL)) {
		if (job)
			flashcache_free_cache_job(job);
		job = NULL;
		dmc->sysctl_error_inject &= ~READ_MISS_JOB_ALLOC_FAIL;
	}
	if (unlikely(job == NULL)) {
		/* 
		 * We have a read miss, and can't allocate a job.
		 * Since we dropped the spinlock, we have to drain any 
		 * pending jobs.
		 */
		DMERR("flashcache: Read (miss) failed ! Can't allocate memory for cache IO, block %lu", 
		      cacheblk->dbn);
		flashcache_bio_endio(bio, -EIO, dmc, NULL);
		atomic_dec(&dmc->cached_blocks);
		spin_lock_irq(&cache_set->set_spin_lock);
		flashcache_hash_remove(dmc, index);
		cacheblk->cache_state &= ~VALID;
		cacheblk->cache_state |= INVALID;
		flashcache_free_pending_jobs(dmc, cacheblk, -EIO);
		cacheblk->cache_state &= ~(BLOCK_IO_INPROG);
		flashcache_invalid_insert(dmc, index);
		spin_unlock_irq(&cache_set->set_spin_lock);
	} else {
		job->action = READDISK; /* Fetch data from the source device */
		atomic_inc(&dmc->nr_jobs);
		dmc->flashcache_stats.disk_reads++;
		dm_io_async_bvec(1, &job->job_io_regions.disk, READ,
				 bio,
				 flashcache_io_callback, job);
		flashcache_clean_set(dmc, set,
				     dmc->sysctl_clean_on_read_miss);
	}
}

static void
flashcache_read(struct cache_c *dmc, struct bio *bio)
{
	int index;
	int res;
	struct cacheblock *cacheblk;
	int queued;
	unsigned long flags;
	
	DPRINTK("Got a %s for %llu (%u bytes)",
	        (bio_rw(bio) == READ ? "READ":"READA"), 
		bio->bi_sector, bio->bi_size);

	flashcache_setlocks_multiget(dmc, bio);
	res = flashcache_lookup(dmc, bio, &index);
	/* Cache Read Hit case */
	if (res > 0) {
		cacheblk = &dmc->cache[index];
		if ((cacheblk->cache_state & VALID) && 
		    (cacheblk->dbn == bio->bi_sector)) {
			flashcache_read_hit(dmc, bio, index);
			return;
		}
	}
	/*
	 * In all cases except for a cache hit (and VALID), test for potential 
	 * invalidations that we need to do.
	 */
	queued = flashcache_inval_blocks(dmc, bio);
	if (queued) {
		if (unlikely(queued < 0))
			flashcache_bio_endio(bio, -EIO, dmc, NULL);
		if ((res > 0) && 
		    (dmc->cache[index].cache_state == INVALID))
			/* 
			 * If happened to pick up an INVALID block, put it back on the 
			 * per cache-set invalid list
			 */
			flashcache_invalid_insert(dmc, index);
		flashcache_setlocks_multidrop(dmc, bio);
		return;
	}

	/*
	 * Locking Note :
	 * We are taking the ioctl_lock holding the cache set multilocks.
	 * The ioctl lock is held for very short durations, and we do not 
	 * (and should not) try to acquire any other locks holding the ioctl
	 * lock.
	 */
	spin_lock_irqsave(&dmc->ioctl_lock, flags);
	if (res == -1 || dmc->write_only_cache || flashcache_uncacheable(dmc, bio)) {
		spin_unlock_irqrestore(&dmc->ioctl_lock, flags);
		/* No room , non-cacheable or sequential i/o means not wanted in cache */
		if ((res > 0) && 
		    (dmc->cache[index].cache_state == INVALID))
			/* 
			 * If happened to pick up an INVALID block, put it back on the 
			 * per cache-set invalid list
			 */
			flashcache_invalid_insert(dmc, index);
		flashcache_setlocks_multidrop(dmc, bio);
		DPRINTK("Cache read: Block %llu(%lu):%s",
			bio->bi_sector, bio->bi_size, "CACHE MISS & NO ROOM");
		if (res == -1)
			flashcache_clean_set(dmc, hash_block(dmc, bio->bi_sector), 0);
		/* Start uncached IO */
		flashcache_start_uncached_io(dmc, bio);
		return;
	} else 
		spin_unlock_irqrestore(&dmc->ioctl_lock, flags);

	/* 
	 * (res == INVALID) Cache Miss 
	 * And we found cache blocks to replace
	 * Claim the cache blocks before giving up the spinlock
	 */
	if (dmc->cache[index].cache_state & VALID) {
		dmc->flashcache_stats.replace++;
		/* 
		 * We are switching the block's identity. Remove it from 
		 * the existing hash queue and re-insert it into a new one 
		 * below, after switching it to the new identity.
		 */
		flashcache_hash_remove(dmc, index);
	} else
		atomic_inc(&dmc->cached_blocks);
	dmc->cache[index].cache_state = VALID | DISKREADINPROG;
	dmc->cache[index].dbn = bio->bi_sector;
	flashcache_hash_insert(dmc, index);
	flashcache_setlocks_multidrop(dmc, bio);

	DPRINTK("Cache read: Block %llu(%lu), index = %d:%s",
		bio->bi_sector, bio->bi_size, index, "CACHE MISS & REPLACE");
	flashcache_read_miss(dmc, bio, index);
}

/*
 * Invalidation might require to grab locks on 2 cache sets. 
 * To prevent Lock Order Reversals (and deadlocks), always grab
 * the cache set locks in ascending order.
 */
static void
flashcache_setlocks_multiget(struct cache_c *dmc, struct bio *bio)
{
	int start_set = hash_block(dmc, bio->bi_sector);
	int end_set = hash_block(dmc, bio->bi_sector + (to_sector(bio->bi_size) - 1));
	
	VERIFY(!in_interrupt());
	spin_lock_irq(&dmc->cache_sets[start_set].set_spin_lock);
	if (start_set != end_set)
		spin_lock(&dmc->cache_sets[end_set].set_spin_lock);
}

static void
flashcache_setlocks_multidrop(struct cache_c *dmc, struct bio *bio)
{
	int start_set = hash_block(dmc, bio->bi_sector);
	int end_set = hash_block(dmc, bio->bi_sector + (to_sector(bio->bi_size) - 1));
	
	VERIFY(!in_interrupt());
	if (start_set != end_set)
		spin_unlock(&dmc->cache_sets[end_set].set_spin_lock);
	spin_unlock_irq(&dmc->cache_sets[start_set].set_spin_lock);
}

/*
 * Invalidate any colliding blocks if they are !BUSY and !DIRTY. If the colliding
 * block is DIRTY, we need to kick off a write. In both cases, we need to wait 
 * until the underlying IO is finished, and then proceed with the invalidation.
 */
static int
flashcache_inval_block_set(struct cache_c *dmc, int set, struct bio *bio, int rw,
			   struct pending_job *pjob)
{
	sector_t io_start = bio->bi_sector;
	sector_t io_end = bio->bi_sector + (to_sector(bio->bi_size) - 1);
	int start_index, end_index, i;
	struct cacheblock *cacheblk;
	
	start_index = dmc->assoc * set;
	end_index = start_index + dmc->assoc;
	for (i = start_index ; i < end_index ; i++) {
		sector_t start_dbn = dmc->cache[i].dbn;
		sector_t end_dbn = start_dbn + dmc->block_size;
		
		cacheblk = &dmc->cache[i];
		if (cacheblk->cache_state & INVALID)
			continue;
		if ((io_start >= start_dbn && io_start < end_dbn) ||
		    (io_end >= start_dbn && io_end < end_dbn)) {
			/* We have a match */
			if (rw == WRITE)
				dmc->flashcache_stats.wr_invalidates++;
			else
				dmc->flashcache_stats.rd_invalidates++;
			if (!(cacheblk->cache_state & (BLOCK_IO_INPROG | DIRTY)) &&
			    (cacheblk->nr_queued == 0)) {
				atomic_dec(&dmc->cached_blocks);
				DPRINTK("Cache invalidate (!BUSY): Block %llu %lx",
					start_dbn, cacheblk->cache_state);
				flashcache_hash_remove(dmc, i);
				cacheblk->cache_state = INVALID;
				flashcache_invalid_insert(dmc, i);
				continue;
			}
			/*
			 * The conflicting block has either IO in progress or is 
			 * Dirty. In all cases, we need to add ourselves to the 
			 * pending queue. Then if the block is dirty, we kick off
			 * an IO to clean the block. 
			 * Note that if the block is dirty and IO is in progress
			 * on it, the do_pending handler will clean the block
			 * and then process the pending queue.
			 */
			flashcache_enq_pending(dmc, bio, i, INVALIDATE, pjob);
			if ((cacheblk->cache_state & (DIRTY | BLOCK_IO_INPROG)) == DIRTY) {
				/* 
				 * Kick off block write.
				 * We can't kick off the write under the spinlock.
				 * Instead, we mark the slot DISKWRITEINPROG, drop 
				 * the spinlock and kick off the write. A block marked
				 * DISKWRITEINPROG cannot change underneath us. 
				 * to enqueue ourselves onto it's pending queue.
				 *
				 * XXX - The dropping of the lock here can be avoided if
				 * we punt the cleaning of the block to the worker thread,
				 * at the cost of a context switch.
				 */
				cacheblk->cache_state |= DISKWRITEINPROG;
				flashcache_clear_fallow(dmc, i);
				flashcache_setlocks_multidrop(dmc, bio);
				flashcache_dirty_writeback(dmc, i); /* Must inc nr_jobs */
				flashcache_setlocks_multiget(dmc, bio);
			}
			return 1;
		}
	}
	return 0;
}

#if 0
static int
flashcache_inval_block_set_v3_checks(struct cache_c *dmc, int set, struct bio *bio)
{
	sector_t io_start = bio->bi_sector;
	sector_t io_end = bio->bi_sector + (to_sector(bio->bi_size) - 1);
	int start_index, end_index, i;
	struct cacheblock *cacheblk;

	start_index = dmc->assoc * set;
	end_index = start_index + dmc->assoc;
	for (i = start_index ; i < end_index ; i++) {
		sector_t start_dbn;
		sector_t end_dbn;
		
		cacheblk = &dmc->cache[i];
		start_dbn = cacheblk->dbn;
		end_dbn = start_dbn + dmc->block_size;
		if (cacheblk->cache_state & INVALID)
			continue;
		if ((io_start >= start_dbn && io_start < end_dbn) ||
		    (io_end >= start_dbn && io_end < end_dbn)) {
			return i;
		}
	}
	return -1;
}
#endif

static int
flashcache_inval_block_set_v3(struct cache_c *dmc, int set, struct bio *bio, 
			      struct pending_job *pjob)
{
	int index;
	struct cacheblock *cacheblk;
	int rw = bio_data_dir(bio);
	sector_t io_start;
	sector_t mask;

	mask = ~((1 << dmc->block_shift) - 1);
	io_start = bio->bi_sector & mask;
	/* Check in per-set hash to see if the overlapping block exists in cache */
	index = flashcache_hash_lookup(dmc, set, io_start);
	if (index == -1) {
#if 0
		index = flashcache_inval_block_set_v3_checks(dmc, set, bio);
		if (index != -1) {
			printk(KERN_ERR "Invalidate: Did not find block on hash "
			       "but found in set %d\n", index);
			printk(KERN_ERR "io_start = %lu bi_sector = %lu bi_end = %lu\n",
			       io_start, 
			       bio->bi_sector, 
			       bio->bi_sector + (to_sector(bio->bi_size) - 1));
			printk(KERN_ERR "cache_state = %x hash_state = %x cacheblk->dbn = %lu\n",
			       dmc->cache[index].cache_state, 
			       dmc->cache[index].hash_state, 			       
			       dmc->cache[index].dbn);
			VERIFY(0);
		}
#endif
		return 0;
	}
	cacheblk = &dmc->cache[index];
	VERIFY(cacheblk->cache_state & VALID);
	/* We have a match */
	if (rw == WRITE) {
		dmc->flashcache_stats.wr_invalidates++;
	} else {
		dmc->flashcache_stats.rd_invalidates++;
	}
	if (!(cacheblk->cache_state & (BLOCK_IO_INPROG | DIRTY)) &&
	    (cacheblk->nr_queued == 0)) {
		atomic_dec(&dmc->cached_blocks);
		DPRINTK("Cache invalidate (!BUSY): Block %llu %lx",
			start_dbn, cacheblk->cache_state);
		flashcache_hash_remove(dmc, index);
		cacheblk->cache_state = INVALID;
		flashcache_invalid_insert(dmc, index);
		return 0;
	}
	/*
	 * The conflicting block has either IO in progress or is 
	 * Dirty. In all cases, we need to add ourselves to the 
	 * pending queue. Then if the block is dirty, we kick off
	 * an IO to clean the block. 
	 * Note that if the block is dirty and IO is in progress
	 * on it, the do_pending handler will clean the block
	 * and then process the pending queue.
	 */
	flashcache_enq_pending(dmc, bio, index, INVALIDATE, pjob);
	if ((cacheblk->cache_state & (DIRTY | BLOCK_IO_INPROG)) == DIRTY) {
		/* 
		 * Kick off block write.
		 * We can't kick off the write under the spinlock.
		 * Instead, we mark the slot DISKWRITEINPROG, drop 
		 * the spinlock and kick off the write. A block marked
		 * DISKWRITEINPROG cannot change underneath us. 
		 * to enqueue ourselves onto it's pending queue.
		 *
		 * XXX - The dropping of the lock here can be avoided if
		 * we punt the cleaning of the block to the worker thread,
		 * at the cost of a context switch.
		 */
		cacheblk->cache_state |= DISKWRITEINPROG;
		flashcache_clear_fallow(dmc, index);
		flashcache_setlocks_multidrop(dmc, bio);
		flashcache_dirty_writeback(dmc, index); /* Must inc nr_jobs */
		flashcache_setlocks_multiget(dmc, bio);
	}
	return 1;
}

static int
flashcache_inval_blocks(struct cache_c *dmc, struct bio *bio)
{	
	sector_t io_start;
	sector_t io_end;
	int start_set, end_set;
	int queued;
	struct pending_job *pjob1, *pjob2;
	sector_t mask;
	
	pjob1 = flashcache_alloc_pending_job(dmc);
	if (unlikely(dmc->sysctl_error_inject & INVAL_PENDING_JOB_ALLOC_FAIL)) {
		if (pjob1) {
			flashcache_free_pending_job(pjob1);
			pjob1 = NULL;
		}
		dmc->sysctl_error_inject &= ~INVAL_PENDING_JOB_ALLOC_FAIL;
	}
	if (pjob1 == NULL) {
		queued = -ENOMEM;
		goto out;
	}
	/* If the on-ssd cache version is < 3, we revert to old style invalidations ! */
	if (dmc->on_ssd_version < 3) {
		pjob2 = flashcache_alloc_pending_job(dmc);
		if (pjob2 == NULL) {
			flashcache_free_pending_job(pjob1);
			queued = -ENOMEM;
			goto out;
		}
		io_start = bio->bi_sector;
		io_end = (bio->bi_sector + (to_sector(bio->bi_size) - 1));
		start_set = hash_block(dmc, io_start);
		end_set = hash_block(dmc, io_end);
		VERIFY(spin_is_locked(&dmc->cache_sets[start_set].set_spin_lock));
		if (start_set != end_set)
			VERIFY(spin_is_locked(&dmc->cache_sets[end_set].set_spin_lock));
		queued = flashcache_inval_block_set(dmc, start_set, bio, 
						    bio_data_dir(bio), pjob1);
		if (queued) {
			flashcache_free_pending_job(pjob2);
			goto out;
		} else
			flashcache_free_pending_job(pjob1);		
		if (start_set != end_set) {
			queued = flashcache_inval_block_set(dmc, end_set, 
							    bio, bio_data_dir(bio), pjob2);
			if (!queued)
				flashcache_free_pending_job(pjob2);
		} else
			flashcache_free_pending_job(pjob2);		
	} else {
		/* 
		 * Assume a 4KB blocksize.
		 * Knowns :
		 * 1) DM will break up IOs at 4KB boundaries.
		 * 2) Flashcache will only cache *exactly* 4KB IOs.
		 * Conclusion :
		 * Flashcache will only cache an IO that begins exactly at a 4KB 
		 * boundary and at a 4KB length !
		 * The incoming IO might be a smaller than 4KB IO, where bi_sector
		 * is NOT 4KB aligned or bi_size < 4KB
		 * To check for overlaps, we simply need to check if the 4KB block
		 * that [bi_sector, bi_sector + bi_size] overlaps with a block that 
		 * is in the cache.
		 */
		mask = ~((1 << dmc->block_shift) - 1);
		io_start = bio->bi_sector & mask;
		start_set = hash_block(dmc, io_start);
		VERIFY(spin_is_locked(&dmc->cache_sets[start_set].set_spin_lock));
		queued = flashcache_inval_block_set_v3(dmc, start_set, bio, pjob1);
		if (queued) {
			goto out;
		} else
			flashcache_free_pending_job(pjob1);		
	}
out:
	return queued;
}

static void
flashcache_write_miss(struct cache_c *dmc, struct bio *bio, int index)
{
	struct cacheblock *cacheblk;
	struct kcached_job *job;
	int queued;
	int set = index / dmc->assoc;
	struct cache_set *cache_set = &dmc->cache_sets[set];

	cacheblk = &dmc->cache[index];
	queued = flashcache_inval_blocks(dmc, bio);
	if (queued) {
		if (cacheblk->cache_state == INVALID)
			/* 
			 * If happened to pick up an INVALID block, put it back on the 
			 * per cache-set invalid list
			 */
			flashcache_invalid_insert(dmc, index);
		flashcache_setlocks_multidrop(dmc, bio);
		if (unlikely(queued < 0))
			flashcache_bio_endio(bio, -EIO, dmc, NULL);
		return;
	}
	if (cacheblk->cache_state & VALID) {
		dmc->flashcache_stats.wr_replace++;
		/* 
		 * We are switching the block's identity. Remove it from 
		 * the existing hash queue and re-insert it into a new one 
		 * below, after switching it to the new identity.
		 */
		flashcache_hash_remove(dmc, index);
	} else
		atomic_inc(&dmc->cached_blocks);
	cacheblk->cache_state = VALID | CACHEWRITEINPROG;
	cacheblk->dbn = bio->bi_sector;
	flashcache_hash_insert(dmc, index);
	flashcache_setlocks_multidrop(dmc, bio);
	job = new_kcached_job(dmc, bio, index);
	if (unlikely(dmc->sysctl_error_inject & WRITE_MISS_JOB_ALLOC_FAIL)) {
		if (job)
			flashcache_free_cache_job(job);
		job = NULL;
		dmc->sysctl_error_inject &= ~WRITE_MISS_JOB_ALLOC_FAIL;
	}
	if (unlikely(job == NULL)) {
		/* 
		 * We have a write miss, and can't allocate a job.
		 * Since we dropped the spinlock, we have to drain any 
		 * pending jobs.
		 */
		DMERR("flashcache: Write (miss) failed ! Can't allocate memory for cache IO, block %lu", 
		      cacheblk->dbn);
		flashcache_bio_endio(bio, -EIO, dmc, NULL);
		atomic_dec(&dmc->cached_blocks);
		spin_lock_irq(&cache_set->set_spin_lock);
		flashcache_hash_remove(dmc, index);
		cacheblk->cache_state &= ~VALID;
		cacheblk->cache_state |= INVALID;
		flashcache_free_pending_jobs(dmc, cacheblk, -EIO);
		cacheblk->cache_state &= ~(BLOCK_IO_INPROG);
		flashcache_invalid_insert(dmc, index);
		spin_unlock_irq(&cache_set->set_spin_lock);
	} else {
		atomic_inc(&dmc->nr_jobs);
		dmc->flashcache_stats.ssd_writes++;
		job->action = WRITECACHE; 
		if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) {
			/* Write data to the cache */		
			dm_io_async_bvec(1, &job->job_io_regions.cache, WRITE, 
					 bio,
					 flashcache_io_callback, job);
		} else {
			VERIFY(dmc->cache_mode == FLASHCACHE_WRITE_THROUGH);
			/* Write data to both disk and cache */
			dm_io_async_bvec(2, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
					 (struct io_region *)&job->job_io_regions, 
#else
					 (struct dm_io_region *)&job->job_io_regions, 
#endif
					 WRITE, 
					 bio,
					 flashcache_io_callback, job);
		}
		flashcache_clean_set(dmc, set,
				     dmc->sysctl_clean_on_write_miss);
	}
}

static void
flashcache_write_hit(struct cache_c *dmc, struct bio *bio, int index)
{
	struct cacheblock *cacheblk;
	struct pending_job *pjob;
	struct kcached_job *job;
	int set = index / dmc->assoc;
	struct cache_set *cache_set = &dmc->cache_sets[set];

	cacheblk = &dmc->cache[index];
	if (!(cacheblk->cache_state & BLOCK_IO_INPROG) && (cacheblk->nr_queued == 0)) {
		if (cacheblk->cache_state & DIRTY)
			dmc->flashcache_stats.dirty_write_hits++;
		dmc->flashcache_stats.write_hits++;
		cacheblk->cache_state |= CACHEWRITEINPROG;
		flashcache_setlocks_multidrop(dmc, bio);
		job = new_kcached_job(dmc, bio, index);
		if (unlikely(dmc->sysctl_error_inject & WRITE_HIT_JOB_ALLOC_FAIL)) {
			if (job)
				flashcache_free_cache_job(job);
			job = NULL;
			dmc->sysctl_error_inject &= ~WRITE_HIT_JOB_ALLOC_FAIL;
		}
		if (unlikely(job == NULL)) {
			/* 
			 * We have a write hit, and can't allocate a job.
			 * Since we dropped the spinlock, we have to drain any 
			 * pending jobs.
			 */
			DMERR("flashcache: Write (hit) failed ! Can't allocate memory for cache IO, block %lu", 
			      cacheblk->dbn);
			flashcache_bio_endio(bio, -EIO, dmc, NULL);
			spin_lock_irq(&cache_set->set_spin_lock);
			flashcache_free_pending_jobs(dmc, cacheblk, -EIO);
			cacheblk->cache_state &= ~(BLOCK_IO_INPROG);
			spin_unlock_irq(&cache_set->set_spin_lock);
		} else {
			DPRINTK("Queue job for %llu", bio->bi_sector);
			atomic_inc(&dmc->nr_jobs);
			dmc->flashcache_stats.ssd_writes++;
			job->action = WRITECACHE;
			if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) {
				/* Write data to the cache */
				dm_io_async_bvec(1, &job->job_io_regions.cache, WRITE, 
						 bio,
						 flashcache_io_callback, job);
				flashcache_clean_set(dmc, index / dmc->assoc, 0);
			} else {
				VERIFY(dmc->cache_mode == FLASHCACHE_WRITE_THROUGH);
				/* Write data to both disk and cache */
				dmc->flashcache_stats.disk_writes++;
				dm_io_async_bvec(2, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
						 (struct io_region *)&job->job_io_regions, 
#else
						 (struct dm_io_region *)&job->job_io_regions, 
#endif
						 WRITE, 
						 bio,
						 flashcache_io_callback, job);				
			}
		}
	} else {
		pjob = flashcache_alloc_pending_job(dmc);
		if (unlikely(dmc->sysctl_error_inject & WRITE_HIT_PENDING_JOB_ALLOC_FAIL)) {
			if (pjob) {
				flashcache_free_pending_job(pjob);
				pjob = NULL;
			}
			dmc->sysctl_error_inject &= ~WRITE_HIT_PENDING_JOB_ALLOC_FAIL;
		}
		if (unlikely(pjob == NULL))
			flashcache_bio_endio(bio, -EIO, dmc, NULL);
		else
			flashcache_enq_pending(dmc, bio, index, WRITECACHE, pjob);
		flashcache_setlocks_multidrop(dmc, bio);
	}
}

static void
flashcache_write(struct cache_c *dmc, struct bio *bio)
{
	int index;
	int res;
	struct cacheblock *cacheblk;
	int queued;

	flashcache_setlocks_multiget(dmc, bio);
	res = flashcache_lookup(dmc, bio, &index);
	if (res != -1) {
		/* Cache Hit */
		cacheblk = &dmc->cache[index];		
		if ((cacheblk->cache_state & VALID) && 
		    (cacheblk->dbn == bio->bi_sector)) {
			/* Cache Hit */
			flashcache_write_hit(dmc, bio, index);
		} else {
			/* Cache Miss, found block to recycle */
			flashcache_write_miss(dmc, bio, index);
		}
		return;
	}
	/*
	 * No room in the set. We cannot write to the cache and have to 
	 * send the request to disk. Before we do that, we must check 
	 * for potential invalidations !
	 */
	queued = flashcache_inval_blocks(dmc, bio);
	flashcache_setlocks_multidrop(dmc, bio);
	if (queued) {
		if (unlikely(queued < 0))
			flashcache_bio_endio(bio, -EIO, dmc, NULL);
		return;
	}
	/* Start uncached IO */
	flashcache_start_uncached_io(dmc, bio);
	flashcache_clean_set(dmc, hash_block(dmc, bio->bi_sector), 0);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
#define bio_barrier(bio)        ((bio)->bi_rw & (1 << BIO_RW_BARRIER))
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
#define bio_barrier(bio)        ((bio)->bi_rw & REQ_HARDBARRIER)
#else
#define bio_barrier(bio)        ((bio)->bi_rw & REQ_FLUSH)
#endif
#endif
#endif

static void
flashcache_do_block_checks(struct cache_c *dmc, struct bio *bio)
{
	sector_t mask;
	sector_t io_start;
	sector_t io_end;

	VERIFY(to_sector(bio->bi_size) <= dmc->block_size);
	mask = ~((1 << dmc->block_shift) - 1);
	io_start = bio->bi_sector & mask;
	io_end = (bio->bi_sector + (to_sector(bio->bi_size) - 1)) & mask;
	/* The incoming bio must NOT straddle a blocksize boundary */
	VERIFY(io_start == io_end);
}

/*
 * Decide the mapping and perform necessary cache operations for a bio request.
 */
int
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
flashcache_map(struct dm_target *ti, struct bio *bio,
	       union map_info *map_context)
#else
flashcache_map(struct dm_target *ti, struct bio *bio)
#endif
{
	struct cache_c *dmc = (struct cache_c *) ti->private;
	int sectors = to_sector(bio->bi_size);
	int queued;
	int uncacheable;
	unsigned long flags;
	
	if (sectors <= 32)
		size_hist[sectors]++;

	if (bio_barrier(bio))
		return -EOPNOTSUPP;

	/*
	 * Basic check to make sure blocks coming in are as we
	 * expect them to be.
	 */
	flashcache_do_block_checks(dmc, bio);

	if (bio_data_dir(bio) == READ)
		dmc->flashcache_stats.reads++;
	else
		dmc->flashcache_stats.writes++;

	spin_lock_irqsave(&dmc->ioctl_lock, flags);
	if (unlikely(dmc->sysctl_pid_do_expiry && 
		     (dmc->whitelist_head || dmc->blacklist_head)))
		flashcache_pid_expiry_all_locked(dmc);
	uncacheable = (unlikely(dmc->bypass_cache) ||
		       (to_sector(bio->bi_size) != dmc->block_size) ||
		       /* 
			* If the op is a READ, we serve it out of cache whenever possible, 
			* regardless of cacheablity 
			*/
		       (bio_data_dir(bio) == WRITE && 
			((dmc->cache_mode == FLASHCACHE_WRITE_AROUND) ||
			 flashcache_uncacheable(dmc, bio))));
	spin_unlock_irqrestore(&dmc->ioctl_lock, flags);
	if (uncacheable) {
		flashcache_setlocks_multiget(dmc, bio);
		queued = flashcache_inval_blocks(dmc, bio);
		flashcache_setlocks_multidrop(dmc, bio);
		if (queued) {
			if (unlikely(queued < 0))
				flashcache_bio_endio(bio, -EIO, dmc, NULL);
		} else {
			/* Start uncached IO */
			flashcache_start_uncached_io(dmc, bio);
		}
	} else {
		if (bio_data_dir(bio) == READ)
			flashcache_read(dmc, bio);
		else
			flashcache_write(dmc, bio);
	}
	return DM_MAPIO_SUBMITTED;
}

/* Block sync support functions */
static void 
flashcache_kcopyd_callback_sync(int read_err, unsigned int write_err, void *context)
{
	struct kcached_job *job = (struct kcached_job *)context;
	struct cache_c *dmc = job->dmc;
	int index = job->index;
	struct cache_set *cache_set = &dmc->cache_sets[index / dmc->assoc];

	VERIFY(!in_interrupt());
	DPRINTK("kcopyd_callback_sync: Index %d", index);
	VERIFY(job->bio == NULL);
	spin_lock_irq(&cache_set->set_spin_lock);
	VERIFY(dmc->cache[index].cache_state & (DISKWRITEINPROG | VALID | DIRTY));
	if (likely(read_err == 0 && write_err == 0)) {
		spin_unlock_irq(&cache_set->set_spin_lock);
		flashcache_md_write(job);
	} else {
		if (read_err)
			read_err = -EIO;
		if (write_err)
			write_err = -EIO;
		/* Disk write failed. We can not purge this cache from flash */
		DMERR("flashcache: Disk writeback failed ! read error %d write error %d block %lu", 
		      -read_err, -write_err, job->job_io_regions.disk.sector);
		VERIFY(cache_set->clean_inprog > 0);
		VERIFY(atomic_read(&dmc->clean_inprog) > 0);
		cache_set->clean_inprog--;
		atomic_dec(&dmc->clean_inprog);
		spin_unlock_irq(&cache_set->set_spin_lock);
		/* Set the error in the job and let do_pending() handle the error */
		if (read_err) {
			dmc->flashcache_errors.ssd_read_errors++;
			job->error = read_err;
		} else {
			dmc->flashcache_errors.disk_write_errors++;			
			job->error = write_err;
		}
		flashcache_do_pending(job);
		flashcache_sync_blocks(dmc);  /* Kick off more cleanings */
		dmc->flashcache_stats.cleanings++;
	}
}

static void
flashcache_dirty_writeback_sync(struct cache_c *dmc, int index)
{
	struct kcached_job *job;
	struct cacheblock *cacheblk = &dmc->cache[index];
	int device_removal = 0;
	int set = index / dmc->assoc;
	struct cache_set *cache_set = &dmc->cache_sets[set];
	
	VERIFY((cacheblk->cache_state & FALLOW_DOCLEAN) == 0);
	DPRINTK("flashcache_dirty_writeback_sync: Index %d", index);
	spin_lock_irq(&cache_set->set_spin_lock);
	VERIFY((cacheblk->cache_state & BLOCK_IO_INPROG) == DISKWRITEINPROG);
	VERIFY(cacheblk->cache_state & DIRTY);
	cache_set->clean_inprog++;
	atomic_inc(&dmc->clean_inprog);
	spin_unlock_irq(&cache_set->set_spin_lock);
	job = new_kcached_job(dmc, NULL, index);
	/*
	 * If the device is being (fast) removed, do not kick off any more cleanings.
	 */
	if (unlikely(atomic_read(&dmc->remove_in_prog) == FAST_REMOVE)) {
		DMERR("flashcache: Dirty Writeback (for set cleaning) aborted for device removal, block %lu", 
		      cacheblk->dbn);
		if (job)
			flashcache_free_cache_job(job);
		job = NULL;
		device_removal = 1;
	}
	if (unlikely(job == NULL)) {
		spin_lock_irq(&cache_set->set_spin_lock);
		cache_set->clean_inprog--;
		atomic_dec(&dmc->clean_inprog);
		flashcache_free_pending_jobs(dmc, cacheblk, -EIO);
		cacheblk->cache_state &= ~(BLOCK_IO_INPROG);
		spin_unlock_irq(&cache_set->set_spin_lock);
		if (device_removal == 0)
			DMERR("flashcache: Dirty Writeback (for sync) failed ! Can't allocate memory, block %lu", 
			      cacheblk->dbn);
	} else {
		job->bio = NULL;
		job->action = WRITEDISK_SYNC;
		atomic_inc(&dmc->nr_jobs);
		dmc->flashcache_stats.ssd_reads++;
		dmc->flashcache_stats.disk_writes++;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
		kcopyd_copy(flashcache_kcp_client, &job->job_io_regions.cache, 1, &job->job_io_regions.disk, 0, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
			    flashcache_kcopyd_callback_sync,
#else
			    (kcopyd_notify_fn) flashcache_kcopyd_callback_sync, 
#endif
			    job);
#else
		dm_kcopyd_copy(flashcache_kcp_client, &job->job_io_regions.cache, 1, &job->job_io_regions.disk, 0, 
			       (dm_kcopyd_notify_fn)flashcache_kcopyd_callback_sync, 
			       (void *)job);
#endif
	}
}

/* 
 * Sync all dirty blocks. We pick off dirty blocks, sort them, merge them with 
 * any contigous blocks we can within the set and fire off the writes.
 */
void
flashcache_sync_blocks(struct cache_c *dmc)
{
	int index;
	struct dbn_index_pair *writes_list = NULL;
	struct dbn_index_pair *set_dirty_list = NULL;
	int nr_writes;
	int i, set;
	struct cacheblock *cacheblk;
	struct cache_set *cache_set;

	/* 
	 * If a (fast) removal of this device is in progress, don't kick off 
	 * any more cleanings. This isn't sufficient though. We still need to
	 * stop cleanings inside flashcache_dirty_writeback_sync() because we could
	 * have started a device remove after tested this here.
	 */
	if ((atomic_read(&dmc->remove_in_prog) == FAST_REMOVE) || 
	    dmc->sysctl_stop_sync)
		return;
	if (atomic_read(&dmc->nr_dirty) == 0 || !(atomic_read(&dmc->sync_index) < dmc->size))
		/* Processed everything ? */
		return;
	if (flashcache_diskclean_alloc(dmc, &writes_list, &set_dirty_list)) {
		dmc->flashcache_errors.memory_alloc_errors++;
		return;
	}
	nr_writes = 0;
	set = -1;
	index = atomic_read(&dmc->sync_index);
	set = index / dmc->assoc;
	cache_set = &dmc->cache_sets[set];
	spin_lock_irq(&cache_set->set_spin_lock);
	while (index < dmc->size && 
	       (nr_writes + atomic_read(&dmc->clean_inprog)) < dmc->max_clean_ios_total) {
		VERIFY(nr_writes <= dmc->assoc);
		if ((index % dmc->assoc) == 0) {
			if (nr_writes > 0) {
				/*
				 * Crossing a set, sort/merge all the IOs collected so
				 * far and issue the writes.
				 */					
				flashcache_merge_writes(dmc, writes_list, set_dirty_list, &nr_writes, set);
				spin_unlock_irq(&cache_set->set_spin_lock);
				for (i = 0 ; i < nr_writes ; i++)
					flashcache_dirty_writeback_sync(dmc, writes_list[i].index);
				nr_writes = 0;
			} else
				spin_unlock_irq(&cache_set->set_spin_lock);
			set = index / dmc->assoc;
			cache_set = &dmc->cache_sets[set];
			spin_lock_irq(&cache_set->set_spin_lock);			
		}
		cacheblk = &dmc->cache[index];
		if ((cacheblk->cache_state & (DIRTY | BLOCK_IO_INPROG)) == DIRTY) {
			cacheblk->cache_state |= DISKWRITEINPROG;
			flashcache_clear_fallow(dmc, index);
			writes_list[nr_writes].dbn = cacheblk->dbn;
			writes_list[nr_writes].index = index;
			nr_writes++;
		}
		index++;
	}
	atomic_set(&dmc->sync_index, index);
	if (nr_writes > 0) {
		VERIFY(set != -1);
		flashcache_merge_writes(dmc, writes_list, set_dirty_list, &nr_writes, set);
		spin_unlock_irq(&cache_set->set_spin_lock);
		for (i = 0 ; i < nr_writes ; i++)
			flashcache_dirty_writeback_sync(dmc, writes_list[i].index);
	} else
		spin_unlock_irq(&cache_set->set_spin_lock);
	flashcache_diskclean_free(dmc, writes_list, set_dirty_list);
}

void
flashcache_sync_all(struct cache_c *dmc)
{
	if (dmc->cache_mode != FLASHCACHE_WRITE_BACK)
		return;
	dmc->sysctl_stop_sync = 0;
	atomic_set(&dmc->sync_index, 0);
	flashcache_sync_blocks(dmc);
}

/*
 * We handle uncached IOs ourselves to deal with the problem of out of ordered
 * IOs corrupting the cache. Consider the case where we get 2 concurent IOs
 * for the same block Write-Read (or a Write-Write). Consider the case where
 * the first Write is uncacheable and the second IO is cacheable. If the 
 * 2 IOs are out-of-ordered below flashcache, then we will cache inconsistent
 * data in flashcache (persistently).
 * 
 * We do invalidations before launching uncacheable IOs to disk. But in case
 * of out of ordering the invalidations before launching the IOs does not help.
 * We need to invalidate after the IO completes.
 * 
 * Doing invalidations after the completion of an uncacheable IO will cause 
 * any overlapping dirty blocks in the cache to be written out and the IO 
 * relaunched. If the overlapping blocks are busy, the IO is relaunched to 
 * disk also (post invalidation). In these 2 cases, we will end up sending
 * 2 disk IOs for the block. But this is a rare case.
 * 
 * When 2 IOs for the same block are sent down (by un co-operating processes)
 * the storage stack is allowed to re-order the IOs at will. So the applications
 * cannot expect any ordering at all.
 * 
 * What we try to avoid here is inconsistencies between disk and the ssd cache.
 */
void 
flashcache_uncached_io_complete(struct kcached_job *job)
{
	struct cache_c *dmc = job->dmc;
	int queued;
	int error = job->error;
	struct bio *bio = job->bio;

	if (unlikely(error)) {
		DMERR("flashcache uncached disk IO error: io error %d block %lu R/w %s", 
		      error, job->job_io_regions.disk.sector, 
		      (bio_data_dir(bio) == WRITE) ? "WRITE" : "READ");
		if (bio_data_dir(bio) == WRITE)
			dmc->flashcache_errors.disk_write_errors++;
		else
			dmc->flashcache_errors.disk_read_errors++;
	}
	flashcache_setlocks_multiget(dmc, bio);
	queued = flashcache_inval_blocks(dmc, bio);
	flashcache_setlocks_multidrop(dmc, bio);
	if (queued) {
		if (unlikely(queued < 0))
			flashcache_bio_endio(bio, -EIO, dmc, NULL);
		/* 
		 * The IO will be re-executed.
		 * The do_pending logic will re-launch the 
		 * disk IO post-invalidation calling start_uncached_io.
		 * This should be a rare occurrence.
		 */
		dmc->flashcache_stats.uncached_io_requeue++;
	} else {
		flashcache_bio_endio(bio, error, dmc, &job->io_start_time);
	}
	flashcache_free_cache_job(job);
	if (atomic_dec_and_test(&dmc->nr_jobs))
		wake_up(&dmc->destroyq);
}

static void 
flashcache_uncached_io_callback(unsigned long error, void *context)
{
	struct kcached_job *job = (struct kcached_job *) context;

	VERIFY(job->index == -1);
	if (unlikely(error))
		job->error = -EIO;
	else
		job->error = 0;
	push_uncached_io_complete(job);
	schedule_work(&_kcached_wq);
}

static void
flashcache_start_uncached_io(struct cache_c *dmc, struct bio *bio)
{
	int is_write = (bio_data_dir(bio) == WRITE);
	struct kcached_job *job;
	
	if (is_write) {
		dmc->flashcache_stats.uncached_writes++;
		dmc->flashcache_stats.disk_writes++;
	} else {
		dmc->flashcache_stats.uncached_reads++;
		dmc->flashcache_stats.disk_reads++;
	}
	job = new_kcached_job(dmc, bio, -1);
	if (unlikely(job == NULL)) {
		flashcache_bio_endio(bio, -EIO, dmc, NULL);
		return;
	}
	atomic_inc(&dmc->nr_jobs);
	dm_io_async_bvec(1, &job->job_io_regions.disk,
			 ((is_write) ? WRITE : READ), 
			 bio,
			 flashcache_uncached_io_callback, job);
}

EXPORT_SYMBOL(flashcache_io_callback);
EXPORT_SYMBOL(flashcache_do_pending_error);
EXPORT_SYMBOL(flashcache_do_pending_noerror);
EXPORT_SYMBOL(flashcache_do_pending);
EXPORT_SYMBOL(flashcache_do_io);
EXPORT_SYMBOL(flashcache_map);
EXPORT_SYMBOL(flashcache_write);
EXPORT_SYMBOL(flashcache_inval_blocks);
EXPORT_SYMBOL(flashcache_inval_block_set);
EXPORT_SYMBOL(flashcache_read);
EXPORT_SYMBOL(flashcache_read_miss);
EXPORT_SYMBOL(flashcache_clean_set);
EXPORT_SYMBOL(flashcache_dirty_writeback);
EXPORT_SYMBOL(flashcache_kcopyd_callback);
EXPORT_SYMBOL(flashcache_lookup);
EXPORT_SYMBOL(flashcache_alloc_md_sector);
EXPORT_SYMBOL(flashcache_free_md_sector);
EXPORT_SYMBOL(flashcache_md_write_callback);
EXPORT_SYMBOL(flashcache_md_write_kickoff);
EXPORT_SYMBOL(flashcache_md_write_done);
EXPORT_SYMBOL(flashcache_md_write);
EXPORT_SYMBOL(hash_block);


