/****************************************************************************
 *  flashcache.h
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

#ifndef FLASHCACHE_H
#define FLASHCACHE_H

#define FLASHCACHE_VERSION		4

#define DEV_PATHLEN	128

#ifdef __KERNEL__

/* Like ASSERT() but always compiled in */

#define VERIFY(x) do { \
	if (unlikely(!(x))) { \
		dump_stack(); \
		panic("VERIFY: assertion (%s) failed at %s (%d)\n", \
		      #x,  __FILE__ , __LINE__);		    \
	} \
} while(0)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#define bi_sector	bi_iter.bi_sector
#define bi_size		bi_iter.bi_size
#define bi_idx		bi_iter.bi_idx
#endif

#define DMC_DEBUG 0
#define DMC_DEBUG_LITE 0

#define DM_MSG_PREFIX "flashcache"
#define DMC_PREFIX "flashcache: "

#if DMC_DEBUG
#define DPRINTK( s, arg... ) printk(DMC_PREFIX s "\n", ##arg)
#else
#define DPRINTK( s, arg... )
#endif

/*
 * Finegrained locking note :
 * All of flashcache used to be protected by a single cache_spin_lock.
 * That has been removed, and per-set spinlocks have been introduced.

struct cache_set : set_spin_lock
Protects cache set and every cacheblock in the cache set.
Can be acquired from softirq paths !

struct cache_md_block_head : md_block_lock
Protects state for the metadata block head.
Can be acquired from softirq paths !

The following locks protect various state within the dmc. All of these
are held for short sections.
struct cache_c : ioctl_lock
struct cache_c : cache_pending_q_spinlock

Lock Ordering. set_spin_lock must be acquired before any of the other 
locks.

set_spin_lock	
(Acquired in increasing order of sets !
If you must acquire 2 set_spin_locks, acquire the lock on set i before
set i+1. Acquiring locks on multiple sets should be done using 
flashcache_setlocks_multiget/drop).
	md_block_lock
	ioctl_lock
	cache_pending_q_spinlock

Important Locking Note :
----------------------
softirq into flashcache (IO completion path) acquires the cache set lock. 
Therefore *any* * (process context) codepath that acquires any other 
spinlock after acquiring the cache set spinlock *must* disable irq's.
Else, we get an irq holding the cache set lock -> other spinlock and
we deadlock on the cache set lock.

These locks are all acquired *after* acquiring the cache set spinlocks,
which means *EVERY* acquisition of these locks must disable irq's to 
address the above race !

Every acquisition of 
	md_block_lock
	ioctl_lock
	cache_pending_q_spinlock
MUST DISABLE IRQs.

 */

/*
 * Block checksums :
 * Block checksums seem a good idea (especially for debugging, I found a couple 
 * of bugs with this), but in practice there are a number of issues with this
 * in production.
 * 1) If a flash write fails, there is no guarantee that the failure was atomic.
 * Some sectors may have been written to flash. If so, the checksum we have
 * is wrong. We could re-read the flash block and recompute the checksum, but
 * the read could fail too. 
 * 2) On a node crash, we could have crashed between the flash data write and the
 * flash metadata update (which updates the new checksum to flash metadata). When
 * we reboot, the checksum we read from metadata is wrong. This is worked around
 * by having the cache load recompute checksums after an unclean shutdown.
 * 3) Checksums require 4 or 8 more bytes per block in terms of metadata overhead.
 * Especially because the metadata is wired into memory.
 * 4) Checksums force us to do a flash metadata IO on a block re-dirty. If we 
 * didn't maintain checksums, we could avoid the metadata IO on a re-dirty.
 * Therefore in production we disable block checksums.
 */
#if 0
#define FLASHCACHE_DO_CHECKSUMS
#endif

#if DMC_DEBUG_LITE
#define DPRINTK_LITE( s, arg... ) printk(DMC_PREFIX s "\n", ##arg)
#else
#define DPRINTK_LITE( s, arg... )
#endif

/* Number of pages for I/O */
#define FLASHCACHE_COPY_PAGES (1024)

/* Default cache parameters */
#define DEFAULT_CACHE_SIZE		65536
#define DEFAULT_CACHE_ASSOC		512
#define DEFAULT_DISK_ASSOC      512     /* 256 KB in 512b sectors */
#define DEFAULT_BLOCK_SIZE		8	/* 4 KB */
#define DEFAULT_MD_BLOCK_SIZE		8	/* 4 KB */
#define DEFAULT_MD_BLOCK_SIZE_BYTES	(DEFAULT_MD_BLOCK_SIZE * 512)	/* 4 KB */
#define FLASHCACHE_MAX_MD_BLOCK_SIZE	128	/* 64 KB */

#define FLASHCACHE_FIFO		0
#define FLASHCACHE_LRU		1

/*
 * The LRU pointers are maintained as set-relative offsets, instead of 
 * pointers. This enables us to store the LRU pointers per cacheblock
 * using 4 bytes instead of 16 bytes. The upshot of this is that we 
 * are required to clamp the associativity at an 8K max.
 */
#define FLASHCACHE_MIN_ASSOC	 256
#define FLASHCACHE_MAX_ASSOC	8192
#define FLASHCACHE_MIN_DISK_ASSOC       256     /* Min Disk Assoc of 128KB in sectors */
#define FLASHCACHE_MAX_DISK_ASSOC       2048    /* Max Disk Assoc of 1MB in sectors */
#define FLASHCACHE_NULL	0xFFFF

struct cacheblock;

struct cache_set {
	spinlock_t 		set_spin_lock;
	u_int32_t		set_fifo_next;
	u_int32_t		set_clean_next;
	u_int16_t		clean_inprog;
	u_int16_t		nr_dirty;
	u_int16_t		dirty_fallow;
	unsigned long 		fallow_tstamp;
	unsigned long 		fallow_next_cleaning;
	/*
	 * 2 LRU queues/cache set.
	 * 1) A block is faulted into the MRU end of the warm list from disk.
	 * 2) When the # of accesses hits a threshold, it is promoted to the
	 * (MRU) end of the hot list. To keep the lists in equilibrium, the
	 * LRU block from the host list moves to the MRU end of the warm list.
	 * 3) Within each list, an access will move the block to the MRU end.
	 * 4) Reclaims happen from the LRU end of the warm list. After reclaim
	 * we move a block from the LRU end of the hot list to the MRU end of
	 * the warm list.
	 */
	u_int16_t               hotlist_lru_head, hotlist_lru_tail;
	u_int16_t               warmlist_lru_head, warmlist_lru_tail;
	u_int16_t               lru_hot_blocks, lru_warm_blocks;
#define NUM_BLOCK_HASH_BUCKETS		512
	u_int16_t		hash_buckets[NUM_BLOCK_HASH_BUCKETS];
	u_int16_t		invalid_head;
};

struct flashcache_errors {
	int	disk_read_errors;
	int	disk_write_errors;
	int	ssd_read_errors;
	int	ssd_write_errors;
	int	memory_alloc_errors;
};

struct flashcache_stats {
	unsigned long reads;		/* Number of reads */
	unsigned long writes;		/* Number of writes */
	unsigned long read_hits;	/* Number of cache hits */
	unsigned long write_hits;	/* Number of write hits (includes dirty write hits) */
	unsigned long dirty_write_hits;	/* Number of "dirty" write hits */
	unsigned long replace;		/* Number of cache replacements */
	unsigned long wr_replace;
	unsigned long wr_invalidates;	/* Number of write invalidations */
	unsigned long rd_invalidates;	/* Number of read invalidations */
	unsigned long pending_inval;	/* Invalidations due to concurrent ios on same block */
#ifdef FLASHCACHE_DO_CHECKSUMS
	unsigned long checksum_store;
	unsigned long checksum_valid;
	unsigned long checksum_invalid;
#endif
	unsigned long enqueues;		/* enqueues on pending queue */
	unsigned long cleanings;
	unsigned long fallow_cleanings;
	unsigned long noroom;		/* No room in set */
	unsigned long md_write_dirty;	/* Metadata sector writes dirtying block */
	unsigned long md_write_clean;	/* Metadata sector writes cleaning block */
	unsigned long md_write_batch;	/* How many md updates did we batch ? */
	unsigned long md_ssd_writes;	/* How many md ssd writes did we do ? */
	unsigned long pid_drops;
	unsigned long pid_adds;
	unsigned long pid_dels;
	unsigned long expiry;
	unsigned long front_merge, back_merge;	/* Write Merging */
	unsigned long uncached_reads, uncached_writes;
	unsigned long uncached_sequential_reads, uncached_sequential_writes;
	unsigned long disk_reads, disk_writes;
	unsigned long ssd_reads, ssd_writes;
	unsigned long uncached_io_requeue;
	unsigned long skipclean;
	unsigned long trim_blocks;
	unsigned long clean_set_ios;
	unsigned long force_clean_block;
	unsigned long lru_promotions;
	unsigned long lru_demotions;
};

struct diskclean_buf_ {
	struct diskclean_buf_ *next;
};

/* 
 * Sequential block history structure - each one
 * records a 'flow' of i/o.
 */
struct sequential_io {
 	sector_t 		most_recent_sector;
	unsigned long		sequential_count;
	/* We use LRU replacement when we need to record a new i/o 'flow' */
	struct sequential_io 	*prev, *next;
};
#define SKIP_SEQUENTIAL_THRESHOLD 0			/* 0 = cache all, >0 = dont cache sequential i/o more than this (kb) */
#define SEQUENTIAL_TRACKER_QUEUE_DEPTH	32		/* How many io 'flows' to track (random i/o will hog many).
							 * This should be large enough so that we don't quickly 
							 * evict sequential i/o when we see some random,
							 * but small enough that searching through it isn't slow
							 * (currently we do linear search, we could consider hashed */
								
	
/*
 * Cache context
 */
struct cache_c {
	struct dm_target	*tgt;
	
	struct dm_dev 		*disk_dev;   /* Source device */
	struct dm_dev 		*cache_dev; /* Cache device */

	int 			on_ssd_version;
	
	struct cacheblock	*cache;	/* Hash table for cache blocks */
	struct cache_set	*cache_sets;
	struct cache_md_block_head *md_blocks_buf;

 	/* None of these change once cache is created */
	unsigned int 	md_block_size;	/* Metadata block size in sectors */
	sector_t 	size;			/* Cache size */
	unsigned int 	assoc;		/* Cache associativity */
	unsigned int 	block_size;	/* Cache block size */
	unsigned int 	block_shift;	/* Cache block size in bits */
	unsigned int 	block_mask;	/* Cache block mask */
	int		md_blocks;		/* Numbers of metadata blocks, including header */
	unsigned int disk_assoc;	/* Disk associativity */
	unsigned int disk_assoc_shift;	/* Disk associativity in bits */
	unsigned int assoc_shift;	/* Consecutive blocks size in bits */
	unsigned int num_sets;		/* Number of cache sets */
	int	cache_mode;
	int	write_only_cache;
	
	wait_queue_head_t destroyq;	/* Wait queue for I/O completion */
	/* XXX - Updates of nr_jobs should happen inside the lock. But doing it outside
	   is OK since the filesystem is unmounted at this point */
	atomic_t nr_jobs;		/* Number of I/O jobs */

#define SLOW_REMOVE    1                                                                                    
#define FAST_REMOVE    2
	atomic_t remove_in_prog;

	int	dirty_thresh_set;	/* Per set dirty threshold to start cleaning */
	int	max_clean_ios_set;	/* Max cleaning IOs per set */
	int	max_clean_ios_total;	/* Total max cleaning IOs */
	atomic_t	clean_inprog;
	atomic_t	sync_index;
	atomic_t	nr_dirty;
	atomic_t 	cached_blocks;	/* Number of cached blocks */
	atomic_t 	pending_jobs_count;
	int		num_block_hash_buckets;

	/* Stats */
	struct flashcache_stats flashcache_stats;

	/* Errors */
	struct flashcache_errors flashcache_errors;

#define IO_LATENCY_GRAN_USECS	250
#define IO_LATENCY_MAX_US_TRACK	10000	/* 10 ms */
#define IO_LATENCY_BUCKETS	(IO_LATENCY_MAX_US_TRACK / IO_LATENCY_GRAN_USECS)
	unsigned long	latency_hist[IO_LATENCY_BUCKETS];
	unsigned long	latency_hist_10ms;
	

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	struct work_struct delayed_clean;
#else
	struct delayed_work delayed_clean;
#endif

	spinlock_t ioctl_lock;	/* XXX- RCU! */
	unsigned long pid_expire_check;

	struct flashcache_cachectl_pid *blacklist_head, *blacklist_tail;
	struct flashcache_cachectl_pid *whitelist_head, *whitelist_tail;
	int num_blacklist_pids, num_whitelist_pids;
	unsigned long blacklist_expire_check, whitelist_expire_check;

	atomic_t hot_list_pct;
	int lru_hot_blocks;
	int lru_warm_blocks;

	spinlock_t	cache_pending_q_spinlock;
#define PENDING_JOB_HASH_SIZE		32
	struct pending_job *pending_job_hashbuckets[PENDING_JOB_HASH_SIZE];

	spinlock_t 		diskclean_list_lock;
	struct diskclean_buf_ 	*diskclean_buf_head;

	spinlock_t		kcopy_job_alloc_lock;
	struct flashcache_copy_job *kcopy_jobs_head;

	struct cache_c	*next_cache;

	void *sysctl_handle;

	// DM virtual device name, stored in superblock and restored on load
	char dm_vdevname[DEV_PATHLEN];
	// real device names are now stored as UUIDs
	char cache_devname[DEV_PATHLEN];
	char disk_devname[DEV_PATHLEN];

	/* 
	 * If the SSD returns errors, in WRITETHRU and WRITEAROUND modes, 
	 * bypass the cache completely. If the SSD dies or is removed, 
	 * we want to continue sending requests to the device.
	 */
	int bypass_cache;

	/* Per device sysctls */
	int sysctl_io_latency_hist;
	int sysctl_do_sync;
	int sysctl_stop_sync;
	int sysctl_dirty_thresh;
	int sysctl_pid_do_expiry;
	int sysctl_max_pids;
	int sysctl_pid_expiry_secs;
	int sysctl_reclaim_policy;
	int sysctl_zerostats;
	int sysctl_error_inject;
	int sysctl_fast_remove;
	int sysctl_cache_all;
	int sysctl_fallow_clean_speed;
	int sysctl_fallow_delay;
	int sysctl_skip_seq_thresh_kb;
	int sysctl_clean_on_read_miss;
	int sysctl_clean_on_write_miss;
	int sysctl_lru_hot_pct;
	int sysctl_lru_promote_thresh;
	int sysctl_new_style_write_merge;

	/* Sequential I/O spotter */
	struct sequential_io	seq_recent_ios[SEQUENTIAL_TRACKER_QUEUE_DEPTH];
	struct sequential_io	*seq_io_head;
	struct sequential_io 	*seq_io_tail;

#define FLASHCACHE_WRITE_CLUST_HIST_SIZE	128
	unsigned long	write_clust_hist[FLASHCACHE_WRITE_CLUST_HIST_SIZE];
	unsigned long	write_clust_hist_ovf;
};

/* kcached/pending job states */
#define READCACHE	1
#define WRITECACHE	2
#define READDISK	3
#define WRITEDISK	4
#define READFILL	5	/* Read Cache Miss Fill */
#define INVALIDATE	6
#define WRITEDISK_SYNC	7

struct kcached_job {
	struct list_head list;
	struct cache_c *dmc;
	struct bio *bio;	/* Original bio */
	struct job_io_regions {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
		struct io_region disk;
		struct io_region cache;
#else
		struct dm_io_region disk;
		struct dm_io_region cache;
#endif
	} job_io_regions;
	int    index;
	int    action;
	int 	error;
	struct flash_cacheblock *md_block;
	struct page_list pl_base[1];
	struct timeval io_start_time;
	struct kcached_job *next;
};

struct pending_job {
	struct bio *bio;
	int	action;	
	int	index;
	struct pending_job *prev, *next;
};

struct flashcache_copy_job {
	struct list_head list;
	struct cache_c *dmc;
	int nr_writes;
	int reads_completed;
	int write_kickoff;
	struct page_list *pl_base;
	struct page_list *pl_list_head;
	struct page **page_base;
	struct kcached_job **job_base;
	struct job_io_regions_ {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
		struct io_region disk;
		struct io_region *cache;
#else
		struct dm_io_region disk;
		struct dm_io_region *cache;
#endif
	} job_io_regions;
	int error;
	spinlock_t copy_job_spinlock;
	struct flashcache_copy_job *next;
};
#endif /* __KERNEL__ */

/* Cache Modes */
enum {
	FLASHCACHE_WRITE_BACK=1,
	FLASHCACHE_WRITE_THROUGH=2,
	FLASHCACHE_WRITE_AROUND=3,
};

/* States of a cache block */
#define INVALID			0x0001
#define VALID			0x0002	/* Valid */
#define DISKREADINPROG		0x0004	/* Read from disk in progress */
#define DISKWRITEINPROG		0x0008	/* Write to disk in progress */
#define CACHEREADINPROG		0x0010	/* Read from cache in progress */
#define CACHEWRITEINPROG	0x0020	/* Write to cache in progress */
#define DIRTY			0x0040	/* Dirty, needs writeback to disk */
/*
 * Old and Dirty blocks are cleaned with a Clock like algorithm. The leading hand
 * marks DIRTY_FALLOW_1. 900 seconds (default) later, the trailing hand comes along and
 * marks DIRTY_FALLOW_2 if DIRTY_FALLOW_1 is already set. If the block was used in the 
 * interim, (DIRTY_FALLOW_1|DIRTY_FALLOW_2) is cleared. Any block that has both 
 * DIRTY_FALLOW_1 and DIRTY_FALLOW_2 marked is considered old and is eligible 
 * for cleaning.
 */
#define DIRTY_FALLOW_1		0x0080	
#define DIRTY_FALLOW_2		0x0100

#define FALLOW_DOCLEAN		(DIRTY_FALLOW_1 | DIRTY_FALLOW_2)
#define BLOCK_IO_INPROG	(DISKREADINPROG | DISKWRITEINPROG | CACHEREADINPROG | CACHEWRITEINPROG)

/* lru_state in cache block */
#define LRU_HOT			0x0001	/* On Hot LRU List */
#define LRU_WARM		0x0002	/* On Warm LRU List */

/* Cache metadata is read by Flashcache utilities */
#ifndef __KERNEL__
typedef u_int64_t sector_t;
#endif

/* On Flash (cache metadata) Structures */
#define CACHE_MD_STATE_DIRTY		0xdeadbeef
#define CACHE_MD_STATE_CLEAN		0xfacecafe
#define CACHE_MD_STATE_FASTCLEAN	0xcafefeed
#define CACHE_MD_STATE_UNSTABLE		0xc8249756

/* Cache block metadata structure */
struct cacheblock {
	u_int16_t	cache_state;
	int16_t 	nr_queued;	/* jobs in pending queue */
	u_int16_t	lru_prev, lru_next;
	u_int8_t        use_cnt;
	u_int8_t        lru_state;
	sector_t 	dbn;	/* Sector number of the cached block */
	u_int16_t	hash_prev, hash_next;
#ifdef FLASHCACHE_DO_CHECKSUMS
	u_int64_t 	checksum;
#endif
} __attribute__((packed));

struct flash_superblock {
	sector_t size;		/* Cache size */
	u_int32_t block_size;	/* Cache block size */
	u_int32_t assoc;	/* Cache associativity */
	u_int32_t cache_sb_state;	/* Clean shutdown ? */
	char cache_devname[DEV_PATHLEN]; /* Contains dm_vdev name as of v2 modifications */
	sector_t cache_devsize;
	char disk_devname[DEV_PATHLEN]; /* underlying block device name (use UUID paths!) */
	sector_t disk_devsize;
	u_int32_t cache_version;
	u_int32_t md_block_size;
	u_int32_t disk_assoc;
	u_int32_t write_only_cache;
};

/* 
 * We do metadata updates only when a block trasitions from DIRTY -> CLEAN
 * or from CLEAN -> DIRTY. Consequently, on an unclean shutdown, we only
 * pick up blocks that are marked (DIRTY | CLEAN), we clean these and stick
 * them in the cache.
 * On a clean shutdown, we will sync the state for every block, and we will
 * load every block back into cache on a restart.
 * 
 * Note: When using larger flashcache metadata blocks, it is important to make 
 * sure that a flash_cacheblock does not straddle 2 sectors. This avoids
 * partial writes of a metadata slot on a powerfail/node crash. Aligning this
 * a 16b or 32b struct avoids that issue.
 * 
 * Note: If a on-ssd flash_cacheblock does not fit exactly within a 512b sector,
 * (ie. if there are any remainder runt bytes), logic in flashcache_conf.c which
 * reads and writes flashcache metadata on create/load/remove will break.
 * 
 * If changing these, make sure they remain a ^2 size !
 */
#ifdef FLASHCACHE_DO_CHECKSUMS
struct flash_cacheblock {
	sector_t 	dbn;	/* Sector number of the cached block */
	u_int64_t 	checksum;
	u_int32_t	cache_state; /* INVALID | VALID | DIRTY */
} __attribute__ ((aligned(32)));
#else
struct flash_cacheblock {
	sector_t 	dbn;	/* Sector number of the cached block */
	u_int32_t	cache_state; /* INVALID | VALID | DIRTY */
} __attribute__ ((aligned(16)));
#endif

#define MD_BLOCK_BYTES(DMC)		((DMC)->md_block_size * 512)
#define MD_SECTORS_PER_BLOCK(DMC)	((DMC)->md_block_size)
#define MD_SLOTS_PER_BLOCK(DMC)		(MD_BLOCK_BYTES(DMC) / (sizeof(struct flash_cacheblock)))
#define INDEX_TO_MD_BLOCK(DMC, INDEX)	((INDEX) / MD_SLOTS_PER_BLOCK(DMC))
#define INDEX_TO_MD_BLOCK_OFFSET(DMC, INDEX)	((INDEX) % MD_SLOTS_PER_BLOCK(DMC))

#define METADATA_IO_BLOCKSIZE		(256*1024)
#define METADATA_IO_NUM_BLOCKS(dmc)	(METADATA_IO_BLOCKSIZE / MD_BLOCK_BYTES(dmc))

#define INDEX_TO_CACHE_ADDR(DMC, INDEX)	\
	(((sector_t)(INDEX) << (DMC)->block_shift) + (DMC)->md_blocks * MD_SECTORS_PER_BLOCK((DMC)))

#define CACHE_ADDR_TO_INDEX(DMC, CACHE_ADDR)	\
	((int)(((CACHE_ADDR) - ((DMC)->md_blocks * MD_SECTORS_PER_BLOCK((DMC)))) >> (DMC)->block_shift))


#ifdef __KERNEL__

/* Cache persistence */
#define CACHE_RELOAD		1
#define CACHE_CREATE		2
#define CACHE_FORCECREATE	3

/* 
 * We have one of these for *every* cache metadata sector, to keep track
 * of metadata ios in progress for blocks covered in this sector. Only
 * one metadata IO per sector can be in progress at any given point in 
 * time
 */
struct cache_md_block_head {
	u_int32_t		nr_in_prog;
	struct kcached_job	*queued_updates, *md_io_inprog;
	spinlock_t		md_block_lock;
};

#define MIN_JOBS 1024

/* Default values for sysctls */
#define DIRTY_THRESH_MIN	10
#define DIRTY_THRESH_MAX	95
#define DIRTY_THRESH_DEF	20

#define MAX_CLEAN_IOS_SET	2
#define MAX_CLEAN_IOS_TOTAL	4
#define MAX_PIDS		100
#define PID_EXPIRY_SECS		60
#define FALLOW_DELAY		(60*15) /* 15 Mins default */
#define FALLOW_SPEED_MIN	1
#define FALLOW_SPEED_MAX	100
#define FALLOW_CLEAN_SPEED	2

#define FLASHCACHE_LRU_HOT_PCT_DEFAULT	50

/* DM async IO mempool sizing */
#define FLASHCACHE_ASYNC_SIZE 1024

enum {
	FLASHCACHE_WHITELIST=0,
	FLASHCACHE_BLACKLIST=1,
};

struct flashcache_cachectl_pid {
	pid_t					pid;
	struct flashcache_cachectl_pid		*next, *prev;
	unsigned long				expiry;
};

struct dbn_index_pair {
	sector_t	dbn;
	int		index;
};

/* Error injection flags */
#define READDISK_ERROR				0x00000001
#define READCACHE_ERROR				0x00000002
#define READFILL_ERROR				0x00000004
#define WRITECACHE_ERROR			0x00000008
#define WRITECACHE_MD_ERROR			0x00000010
#define WRITEDISK_MD_ERROR			0x00000020
#define KCOPYD_CALLBACK_ERROR			0x00000040
#define DIRTY_WRITEBACK_JOB_ALLOC_FAIL		0x00000080
#define READ_MISS_JOB_ALLOC_FAIL		0x00000100
#define READ_HIT_JOB_ALLOC_FAIL			0x00000200
#define READ_HIT_PENDING_JOB_ALLOC_FAIL		0x00000400
#define INVAL_PENDING_JOB_ALLOC_FAIL		0x00000800
#define WRITE_HIT_JOB_ALLOC_FAIL		0x00001000
#define WRITE_HIT_PENDING_JOB_ALLOC_FAIL	0x00002000
#define WRITE_MISS_JOB_ALLOC_FAIL		0x00004000
#define WRITES_LIST_ALLOC_FAIL			0x00008000
#define MD_ALLOC_SECTOR_ERROR			0x00010000

/* Inject a 5s delay between syncing blocks and metadata */
#define FLASHCACHE_SYNC_REMOVE_DELAY		5000

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
int flashcache_map(struct dm_target *ti, struct bio *bio,
		   union map_info *map_context);
#else
int flashcache_map(struct dm_target *ti, struct bio *bio);
#endif
int flashcache_ctr(struct dm_target *ti, unsigned int argc,
		   char **argv);
void flashcache_dtr(struct dm_target *ti);

struct kcached_job *flashcache_alloc_cache_job(void);
void flashcache_free_cache_job(struct kcached_job *job);
struct pending_job *flashcache_alloc_pending_job(struct cache_c *dmc);
void flashcache_free_pending_job(struct pending_job *job);
#ifdef FLASHCACHE_DO_CHECKSUMS
u_int64_t flashcache_compute_checksum(struct bio *bio);
void flashcache_store_checksum(struct kcached_job *job);
int flashcache_validate_checksum(struct kcached_job *job);
int flashcache_read_compute_checksum(struct cache_c *dmc, int index, void *block);
#endif
struct kcached_job *pop(struct list_head *jobs);
void push(struct list_head *jobs, struct kcached_job *job);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
void do_work(void *unused);
#else
void do_work(struct work_struct *unused);
#endif
struct kcached_job *new_kcached_job(struct cache_c *dmc, struct bio* bio,
				    int index);
void push_pending(struct kcached_job *job);
void push_io(struct kcached_job *job);
void push_md_io(struct kcached_job *job);
void push_md_complete(struct kcached_job *job);
void push_uncached_io_complete(struct kcached_job *job);
int flashcache_pending_empty(void);
int flashcache_io_empty(void);
int flashcache_md_io_empty(void);
int flashcache_md_complete_empty(void);
void flashcache_md_write_done(struct kcached_job *job);
void flashcache_do_pending(struct kcached_job *job);
void flashcache_free_pending_jobs(struct cache_c *dmc, struct cacheblock *cacheblk, 
				  int error);

void flashcache_md_write(struct kcached_job *job);
void flashcache_md_write_kickoff(struct kcached_job *job);
void flashcache_do_io(struct kcached_job *job);
void flashcache_uncached_io_complete(struct kcached_job *job);
void flashcache_clean_set(struct cache_c *dmc, int set, int force_clean_blocks);
void flashcache_sync_all(struct cache_c *dmc);
void flashcache_reclaim_fifo_get_old_block(struct cache_c *dmc, int start_index, int *index);
void flashcache_reclaim_lru_get_old_block(struct cache_c *dmc, int start_index, int *index);
void flashcache_reclaim_init_lru_lists(struct cache_c *dmc);
void flashcache_lru_accessed(struct cache_c *dmc, int index);
void flashcache_reclaim_rebalance_lru(struct cache_c *dmc, int new_lru_hot_pct);
void flashcache_merge_writes(struct cache_c *dmc, 
			     struct dbn_index_pair *writes_list, 
			     struct dbn_index_pair *set_dirty_list,
			     int *nr_writes, int set);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
int flashcache_dm_io_sync_vm(struct cache_c *dmc, struct io_region *where, 
			     int rw, void *data);
#else
int flashcache_dm_io_sync_vm(struct cache_c *dmc, struct dm_io_region *where, 
			     int rw, void *data);
#endif
void flashcache_update_sync_progress(struct cache_c *dmc);
void flashcache_enq_pending(struct cache_c *dmc, struct bio* bio,
			    int index, int action, struct pending_job *job);
struct pending_job *flashcache_deq_pending(struct cache_c *dmc, int index);

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
		     void *context);
#endif

void flashcache_detect_fallow(struct cache_c *dmc, int index);
void flashcache_clear_fallow(struct cache_c *dmc, int index);

void flashcache_bio_endio(struct bio *bio, int error, 
			  struct cache_c *dmc, struct timeval *io_start_time);

/* procfs */
void flashcache_module_procfs_init(void);
void flashcache_module_procfs_release(void);
void flashcache_ctr_procfs(struct cache_c *dmc);
void flashcache_dtr_procfs(struct cache_c *dmc);

void flashcache_hash_init(struct cache_c *dmc);
void flashcache_hash_destroy(struct cache_c *dmc);
void flashcache_hash_remove(struct cache_c *dmc, int index);
int flashcache_hash_lookup(struct cache_c *dmc, int set,
			   sector_t dbn);
void flashcache_hash_insert(struct cache_c *dmc, int index);

void flashcache_invalid_insert(struct cache_c *dmc, int index);
void flashcache_invalid_remove(struct cache_c *dmc, int index);
int flashcache_invalid_get(struct cache_c *dmc, int set);

int flashcache_diskclean_init(struct cache_c *dmc);
void flashcache_diskclean_destroy(struct cache_c *dmc);
int flashcache_diskclean_alloc(struct cache_c *dmc, 
			       struct dbn_index_pair **buf1, struct dbn_index_pair **buf2);
void flashcache_diskclean_free(struct cache_c *dmc, struct dbn_index_pair *buf1, 
			       struct dbn_index_pair *buf2);

unsigned long hash_block(struct cache_c *dmc, sector_t dbn);
void flashcache_copy_data(struct cache_c *dmc, struct cache_set *cache_set,
			  int nr_writes, struct dbn_index_pair *writes_list);

void push_cleaning_read_complete(struct flashcache_copy_job *job);
void push_cleaning_write_complete(struct flashcache_copy_job *job);
void flashcache_clean_write_kickoff(struct flashcache_copy_job *job);
void flashcache_clean_md_write_kickoff(struct flashcache_copy_job *job);

int flashcache_kcopy_init(struct cache_c *dmc);
void flashcache_kcopy_destroy(struct cache_c *dmc);


#endif /* __KERNEL__ */

#endif
