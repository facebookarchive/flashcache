/****************************************************************************
 *  flashcache_wt.h
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

/* Like ASSERT() but always compiled in */

#define VERIFY(x) do { \
	if (unlikely(!(x))) { \
		dump_stack(); \
		panic("VERIFY: assertion (%s) failed at %s (%d)\n", \
		      #x,  __FILE__ , __LINE__);		    \
	} \
} while(0)

#define DMC_DEBUG 0
#define DMC_DEBUG_LITE 0

#define DM_MSG_PREFIX "flashcache-wt"
#define DMC_PREFIX "flashcache-wt: "

#if DMC_DEBUG
#define DPRINTK( s, arg... ) printk(DMC_PREFIX s "\n", ##arg)
#else
#define DPRINTK( s, arg... )
#endif

#if DMC_DEBUG_LITE
#define DPRINTK_LITE( s, arg... ) printk(DMC_PREFIX s "\n", ##arg)
#else
#define DPRINTK_LITE( s, arg... )
#endif

#define READCACHE	1
#define WRITECACHE	2
#define READSOURCE	3
#define WRITESOURCE	4
#define SOURCEIO_DONE	5
#define READCACHE_DONE	6

/* Default cache parameters */
#define DEFAULT_CACHE_SIZE	65536
#define DEFAULT_CACHE_ASSOC	512
#define DEFAULT_BLOCK_SIZE	8	/* 4 KB */
#define CONSECUTIVE_BLOCKS	512

/* States of a cache block */
#define INVALID		0
#define VALID		1	/* Valid */
#define INPROG		2	/* IO (cache fill) is in progress */
#define CACHEREADINPROG	3	/* cache read in progress, don't recycle */
#define INPROG_INVALID	4	/* Write invalidated during a refill */

#define DEV_PATHLEN	128

/*
 * Cache context
 */
struct cache_c {
	struct dm_target	*tgt;
	
	struct dm_dev 		*disk_dev;   /* Source device */
	struct dm_dev 		*cache_dev; /* Cache device */

	spinlock_t		cache_spin_lock;
	struct cacheblock	*cache;	/* Hash table for cache blocks */
	u_int8_t 		*cache_state;
	u_int32_t		*set_lru_next;

	int			write_around_mode;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	struct dm_io_client *io_client; /* Client memory pool*/
#endif
	
	sector_t size;			/* Cache size */
	unsigned int assoc;		/* Cache associativity */
	unsigned int block_size;	/* Cache block size */
	unsigned int block_shift;	/* Cache block size in bits */
	unsigned int block_mask;	/* Cache block mask */
	unsigned int consecutive_shift;	/* Consecutive blocks size in bits */

	wait_queue_head_t destroyq;	/* Wait queue for I/O completion */
	atomic_t nr_jobs;		/* Number of I/O jobs */

	/* Stats */
	unsigned long reads;		/* Number of reads */
	unsigned long writes;		/* Number of writes */
	unsigned long cache_hits;	/* Number of cache hits */
	unsigned long replace;		/* Number of cache replacements */
	unsigned long wr_invalidates;	/* Number of write invalidations */
	unsigned long rd_invalidates;	/* Number of read invalidations */
	unsigned long cached_blocks;	/* Number of cached blocks */

#ifdef FLASHCACHE_WT_CHECKSUMS
	unsigned long checksum_store;
	unsigned long checksum_valid;
	unsigned long checksum_invalid
#endif /* FLASHCACHE_WT_CHECKSUMS */

	unsigned long cache_wr_replace;
	unsigned long uncached_reads;
	unsigned long uncached_writes;
	unsigned long cache_reads, cache_writes;
	unsigned long disk_reads, disk_writes;	

	char cache_devname[DEV_PATHLEN];
	char disk_devname[DEV_PATHLEN];
};

/* Cache block metadata structure */
struct cacheblock {
	sector_t dbn;		/* Sector number of the cached block */
#ifdef FLASHCACHE_WT_CHECKSUMS
	u_int64_t checksum;
#endif /* FLASHCACHE_WT_CHECKSUMS */
};

/* Structure for a kcached job */
struct kcached_job {
	struct list_head list;
	struct cache_c *dmc;
	struct bio *bio;	/* Original bio */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	struct io_region disk;
	struct io_region cache;
#else
	struct dm_io_region disk;
	struct dm_io_region cache;
#endif
	int    index;
	int rw;
	int error;
};

#define FLASHCACHE_WT_MIN_JOBS 1024

/* DM async IO mempool sizing */
#define FLASHCACHE_ASYNC_SIZE 1024

/* Number of pages for I/O */
#define FLASHCACHE_COPY_PAGES (1024)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define flashcache_bio_endio(BIO, ERROR)	bio_endio((BIO), (BIO)->bi_size, (ERROR))
#else
#define flashcache_bio_endio(BIO, ERROR)	bio_endio((BIO), (ERROR))
#endif
