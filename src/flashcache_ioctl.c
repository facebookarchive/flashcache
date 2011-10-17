/****************************************************************************
 *  flashcache_ioctl.c
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

static int flashcache_find_pid_locked(struct cache_c *dmc, pid_t pid, 
				      int which_list);
static void flashcache_del_pid_locked(struct cache_c *dmc, pid_t pid, 
				      int which_list);

static int
flashcache_find_pid_locked(struct cache_c *dmc, pid_t pid, 
			   int which_list)
{
	struct flashcache_cachectl_pid *pid_list;
	
	pid_list = ((which_list == FLASHCACHE_WHITELIST) ? 
		    dmc->whitelist_head : dmc->blacklist_head);
	for ( ; pid_list != NULL ; pid_list = pid_list->next) {
		if (pid_list->pid == pid)
			return 1;
	}
	return 0;	
}

static void
flashcache_drop_pids(struct cache_c *dmc, int which_list)
{
	if (which_list == FLASHCACHE_WHITELIST) {
		while (dmc->num_whitelist_pids >= dmc->sysctl_max_pids) {
			VERIFY(dmc->whitelist_head != NULL);
			flashcache_del_pid_locked(dmc, dmc->whitelist_tail->pid,
						  which_list);
			dmc->flashcache_stats.pid_drops++;
		}
	} else {
		while (dmc->num_blacklist_pids >= dmc->sysctl_max_pids) {
			VERIFY(dmc->blacklist_head != NULL);
			flashcache_del_pid_locked(dmc, dmc->blacklist_tail->pid,
						  which_list);
			dmc->flashcache_stats.pid_drops++;
		}		
	}
}

static void
flashcache_add_pid(struct cache_c *dmc, pid_t pid, int which_list)
{
	struct flashcache_cachectl_pid *new;
 	unsigned long flags;

	new = kmalloc(sizeof(struct flashcache_cachectl_pid), GFP_KERNEL);
	new->pid = pid;
	new->next = NULL;
	new->expiry = jiffies + dmc->sysctl_pid_expiry_secs * HZ;
	spin_lock_irqsave(&dmc->cache_spin_lock, flags);
	if (which_list == FLASHCACHE_WHITELIST) {
		if (dmc->num_whitelist_pids > dmc->sysctl_max_pids)
			flashcache_drop_pids(dmc, which_list);
	} else {
		if (dmc->num_blacklist_pids > dmc->sysctl_max_pids)
			flashcache_drop_pids(dmc, which_list);		
	}
	if (flashcache_find_pid_locked(dmc, pid, which_list) == 0) {
		struct flashcache_cachectl_pid **head, **tail;
		
		if (which_list == FLASHCACHE_WHITELIST) {
			head = &dmc->whitelist_head;
			tail = &dmc->whitelist_tail;
		} else {
			head = &dmc->blacklist_head;
			tail = &dmc->blacklist_tail;
		}
		/* Add the new pid to the tail */
		new->prev = *tail;
		if (*head == NULL) {
			VERIFY(*tail == NULL);
			*head = new;
		} else {
			VERIFY(*tail != NULL);
			(*tail)->next = new;
		}
		*tail = new;
		if (which_list == FLASHCACHE_WHITELIST)
			dmc->num_whitelist_pids++;
		else
			dmc->num_blacklist_pids++;
		dmc->flashcache_stats.pid_adds++;
		/* When adding the first entry to list, set expiry check timeout */
		if (*head == new)
			dmc->pid_expire_check = 
				jiffies + ((dmc->sysctl_pid_expiry_secs + 1) * HZ);
	} else
		kfree(new);
	spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
	return;
}

static void
flashcache_del_pid_locked(struct cache_c *dmc, pid_t pid, int which_list)
{
	struct flashcache_cachectl_pid *node;
	struct flashcache_cachectl_pid **head, **tail;
	
	if (which_list == FLASHCACHE_WHITELIST) {
		head = &dmc->whitelist_head;
		tail = &dmc->whitelist_tail;
	} else {
		head = &dmc->blacklist_head;
		tail = &dmc->blacklist_tail;
	}
	for (node = *tail ; node != NULL ; node = node->prev) {
		if (which_list == FLASHCACHE_WHITELIST)
			VERIFY(dmc->num_whitelist_pids > 0);
		else
			VERIFY(dmc->num_blacklist_pids > 0);
		if (node->pid == pid) {
			if (node->prev == NULL) {
				*head = node->next;
				if (node->next)
					node->next->prev = NULL;
			} else
				node->prev->next = node->next;
			if (node->next == NULL) {
				*tail = node->prev;
				if (node->prev)
					node->prev->next = NULL;
			} else
				node->next->prev = node->prev;
			kfree(node);
			dmc->flashcache_stats.pid_dels++;
			if (which_list == FLASHCACHE_WHITELIST)
				dmc->num_whitelist_pids--;
			else
				dmc->num_blacklist_pids--;
			return;
		}
	}
}

static void
flashcache_del_pid(struct cache_c *dmc, pid_t pid, int which_list)
{
	unsigned long flags;

	spin_lock_irqsave(&dmc->cache_spin_lock, flags);
	flashcache_del_pid_locked(dmc, pid, which_list);
	spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
}

/*
 * This removes all "dead" pids. Pids that may have not cleaned up.
 */
void
flashcache_del_all_pids(struct cache_c *dmc, int which_list, int force)
{
	struct flashcache_cachectl_pid *node, **tail;
	unsigned long flags;
	
	if (which_list == FLASHCACHE_WHITELIST)
		tail = &dmc->whitelist_tail;
	else
		tail = &dmc->blacklist_tail;
	rcu_read_lock();
	spin_lock_irqsave(&dmc->cache_spin_lock, flags);
	node = *tail;
	while (node != NULL) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
		if (force == 0) {
			struct task_struct *task;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,23)
			task = find_task_by_pid_type(PIDTYPE_PID, node->pid);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
			task = find_task_by_vpid(node->pid);
#else
			ask = pid_task(find_vpid(node->pid), PIDTYPE_PID);
#endif
			/*
			 * If that task was found, don't remove it !
			 * This prevents a rogue "delete all" from removing
			 * every thread from the list.
			 */
			if (task) {
				node = node->prev;
				continue;
			}
		}
#endif
		flashcache_del_pid_locked(dmc, node->pid, which_list);
		node = *tail;
	}
	spin_unlock_irqrestore(&dmc->cache_spin_lock, flags);
	rcu_read_unlock();
}

static void
flashcache_pid_expiry_list_locked(struct cache_c *dmc, int which_list)
{
	struct flashcache_cachectl_pid **head, **tail, *node;
	
	if (which_list == FLASHCACHE_WHITELIST) {
		head = &dmc->whitelist_head;
		tail = &dmc->whitelist_tail;
	} else {
		head = &dmc->blacklist_head;
		tail = &dmc->blacklist_tail;
	}
	for (node = *head ; node != NULL ; node = node->next) {
		if (which_list == FLASHCACHE_WHITELIST)
			VERIFY(dmc->num_whitelist_pids > 0);
		else
			VERIFY(dmc->num_blacklist_pids > 0);
		if (time_after(node->expiry, jiffies))
			continue;
		if (node->prev == NULL) {
			*head = node->next;
			if (node->next)
				node->next->prev = NULL;
		} else
			node->prev->next = node->next;
		if (node->next == NULL) {
			*tail = node->prev;
			if (node->prev)
				node->prev->next = NULL;
		} else
			node->next->prev = node->prev;
		kfree(node);
		if (which_list == FLASHCACHE_WHITELIST)
			dmc->num_whitelist_pids--;
		else
			dmc->num_blacklist_pids--;
		dmc->flashcache_stats.expiry++;
	}
}

void
flashcache_pid_expiry_all_locked(struct cache_c *dmc)
{
	if (likely(time_before(jiffies, dmc->pid_expire_check)))
		return;
	flashcache_pid_expiry_list_locked(dmc, FLASHCACHE_WHITELIST);
	flashcache_pid_expiry_list_locked(dmc, FLASHCACHE_BLACKLIST);
	dmc->pid_expire_check = jiffies + (dmc->sysctl_pid_expiry_secs + 1) * HZ;
}

/*
 * Is the IO cacheable, depending on global cacheability and the white/black
 * lists ? This function is a bit confusing because we want to support inheritance
 * of cacheability across pthreads (so we use the tgid). But when an entire thread
 * group is added to the white/black list, we want to provide for exceptions for 
 * individual threads as well.
 * The Rules (in decreasing order of priority) :
 * 1) Check the pid (thread id) against the list. 
 * 2) Check the tgid against the list, then check for exceptions within the tgid.
 * 3) Possibly don't cache sequential i/o.
 */
int
flashcache_uncacheable(struct cache_c *dmc, struct bio *bio)
{
	int dontcache;
	
	if (dmc->sysctl_cache_all) {
		/* If the tid has been blacklisted, we don't cache at all.
		   This overrides everything else */
		dontcache = flashcache_find_pid_locked(dmc, current->pid, 
						       FLASHCACHE_BLACKLIST);
		if (dontcache)
			goto out;
		/* Is the tgid in the blacklist ? */
		dontcache = flashcache_find_pid_locked(dmc, current->tgid, 
						       FLASHCACHE_BLACKLIST);
		/* 
		 * If we found the tgid in the blacklist, is there a whitelist
		 * exception entered for this thread ?
		 */
		if (dontcache) {
			if (flashcache_find_pid_locked(dmc, current->pid, 
						       FLASHCACHE_WHITELIST)) {
				dontcache = 0;
				goto out;
			}
		}

		/* Finally, if we are neither in a whitelist or a blacklist,
		 * do a final check to see if this is sequential i/o.  If
		 * the relevant sysctl is set, we will skip it.
		 */
		dontcache = skip_sequential_io(dmc, bio);
			
	} else { /* cache nothing */
		/* If the tid has been whitelisted, we cache 
		   This overrides everything else */
		dontcache = !flashcache_find_pid_locked(dmc, current->pid, 
							FLASHCACHE_WHITELIST);
		if (!dontcache)
			goto out;
		/* Is the tgid in the whitelist ? */
		dontcache = !flashcache_find_pid_locked(dmc, current->tgid, 
							FLASHCACHE_WHITELIST);
		/* 
		 * If we found the tgid in the whitelist, is there a black list 
		 * exception entered for this thread ?
		 */
		if (!dontcache) {
			if (flashcache_find_pid_locked(dmc, current->pid, 
						       FLASHCACHE_BLACKLIST))
				dontcache = 1;
		}
		/* No sequential handling here.  If we add to the whitelist,
		 * everything is cached, sequential or not.
  		 */
	}
out:
	return dontcache;
}

/* Below 2 functions manage the LRU cache of recent IO 'flows'.  
 * A sequential IO will only take up one slot (we keep updating the 
 * last sector seen) but random IO will quickly fill multiple slots.  
 * We allocate the LRU cache from a small fixed sized buffer at startup. 
 */
void
seq_io_remove_from_lru(struct cache_c *dmc, struct sequential_io *seqio)
{
	if (seqio->prev != NULL) 
		seqio->prev->next = seqio->next;
	else {
		VERIFY(dmc->seq_io_head == seqio);
		dmc->seq_io_head = seqio->next;
	}
	if (seqio->next != NULL)
		seqio->next->prev = seqio->prev;
	else {
		VERIFY(dmc->seq_io_tail == seqio);
		dmc->seq_io_tail = seqio->prev;
	}
}

void
seq_io_move_to_lruhead(struct cache_c *dmc, struct sequential_io *seqio)
{
	if (likely(seqio->prev != NULL || seqio->next != NULL))
		seq_io_remove_from_lru(dmc, seqio);
	/* Add it to LRU head */
	if (dmc->seq_io_head != NULL)
		dmc->seq_io_head->prev = seqio;
	seqio->next = dmc->seq_io_head;
	seqio->prev = NULL;
	dmc->seq_io_head = seqio;
}
       

/* Look for and maybe skip sequential i/o.  
 *
 * Since          performance(SSD) >> performance(HDD) for random i/o,
 * but            performance(SSD) ~= performance(HDD) for sequential i/o,
 * it may be optimal to save (presumably expensive) SSD cache space for random i/o only.
 *
 * We don't know whether a single request is part of a big sequential read/write.
 * So all we can do is monitor a few requests, and try to spot if they are
 * continuations of a recent 'flow' of i/o.  After several contiguous blocks we consider
 * it sequential.
 *
 * You can tune the threshold with the sysctl skip_seq_thresh_kb (e.g. 64 = 64kb),
 * or cache all i/o (without checking whether random or sequential) with skip_seq_thresh_kb = 0.
 */
int 
skip_sequential_io(struct cache_c *dmc, struct bio *bio)
{
	struct sequential_io *seqio;
	int sequential = 0;	/* Saw > 1 in a row? */
	int skip       = 0;	/* Enough sequential to hit the threshold */

	/* sysctl skip sequential threshold = 0 : disable, cache all sequential and random i/o.
	 * This is the default. */	 
	if (dmc->sysctl_skip_seq_thresh_kb == 0)  {
		skip = 0;	/* Redundant, for emphasis */
		goto out;
	}

	/* locking : We are already within cache_spin_lock so we don't
	 * need to explicitly lock our data structures.
 	 */

	/* Is it a continuation of recent i/o?  Try to find a match.  */
	DPRINTK("skip_sequential_io: searching for %ld", bio->bi_sector);
	/* search the list in LRU order so single sequential flow hits first slot */
	for (seqio = dmc->seq_io_head; seqio != NULL && sequential == 0; seqio = seqio->next) { 

		if (bio->bi_sector == seqio->most_recent_sector) {
			/* Reread or write same sector again.  Ignore but move to head */
			DPRINTK("skip_sequential_io: repeat");
			sequential = 1;
			if (dmc->seq_io_head != seqio)
				seq_io_move_to_lruhead(dmc, seqio);
		}
		/* i/o to one block more than the previous i/o = sequential */	
		else if (bio->bi_sector == seqio->most_recent_sector + dmc->block_size) {
			DPRINTK("skip_sequential_io: sequential found");
			/* Update stats.  */
			seqio->most_recent_sector = bio->bi_sector;
			seqio->sequential_count++;
			sequential = 1;

			/* And move to head, if not head already */
			if (dmc->seq_io_head != seqio)
				seq_io_move_to_lruhead(dmc, seqio);

			/* Is it now sequential enough to be sure? (threshold expressed in kb) */
			if (to_bytes(seqio->sequential_count * dmc->block_size) > dmc->sysctl_skip_seq_thresh_kb * 1024) {
				DPRINTK("skip_sequential_io: Sequential i/o detected, seq count now %lu", 
					seqio->sequential_count);
				/* Sufficiently sequential */
				skip = 1;
			}
		}
	}
	if (!sequential) {
		/* Record the start of some new i/o, maybe we'll spot it as 
		 * sequential soon.  */
		DPRINTK("skip_sequential_io: concluded that its random i/o");

		seqio = dmc->seq_io_tail;
		seq_io_move_to_lruhead(dmc, seqio);

		DPRINTK("skip_sequential_io: fill in data");

		/* Fill in data */
		seqio->most_recent_sector = bio->bi_sector;
		seqio->sequential_count	  = 1;
	}
	DPRINTK("skip_sequential_io: complete.");
out:
	if (skip) {
		if (bio_data_dir(bio) == READ)
	        	dmc->flashcache_stats.uncached_sequential_reads++;
		else 
	        	dmc->flashcache_stats.uncached_sequential_writes++;
	}

	return skip;
}


/*
 * Add/del pids whose IOs should be non-cacheable.
 * We limit this number to 100 (arbitrary and sysctl'able).
 * We also add an expiry to each entry (defaluts at 60 sec,
 * arbitrary and sysctlable).
 * This is needed because Linux lacks an "at_exit()" hook
 * that modules can supply to do any cleanup on process 
 * exit, for cases where the process dies after marking itself
 * non-cacheable.
 */
int 
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,27)
flashcache_ioctl(struct dm_target *ti, struct inode *inode,
		 struct file *filp, unsigned int cmd,
		 unsigned long arg)
#else
flashcache_ioctl(struct dm_target *ti, unsigned int cmd, unsigned long arg)
#endif
{
	struct cache_c *dmc = (struct cache_c *) ti->private;
	struct block_device *bdev = dmc->disk_dev->bdev;
	struct file fake_file = {};
	struct dentry fake_dentry = {};
	pid_t pid;

	switch(cmd) {
	case FLASHCACHEADDBLACKLIST:
		if (copy_from_user(&pid, (pid_t *)arg, sizeof(pid_t)))
			return -EFAULT;
		flashcache_add_pid(dmc, pid, FLASHCACHE_BLACKLIST);
		return 0;
	case FLASHCACHEDELBLACKLIST:
		if (copy_from_user(&pid, (pid_t *)arg, sizeof(pid_t)))
			return -EFAULT;
		flashcache_del_pid(dmc, pid, FLASHCACHE_BLACKLIST);
		return 0;
	case FLASHCACHEDELALLBLACKLIST:
		flashcache_del_all_pids(dmc, FLASHCACHE_BLACKLIST, 0);
		return 0;
	case FLASHCACHEADDWHITELIST:
		if (copy_from_user(&pid, (pid_t *)arg, sizeof(pid_t)))
			return -EFAULT;
		flashcache_add_pid(dmc, pid, FLASHCACHE_WHITELIST);
		return 0;
	case FLASHCACHEDELWHITELIST:
		if (copy_from_user(&pid, (pid_t *)arg, sizeof(pid_t)))
			return -EFAULT;
		flashcache_del_pid(dmc, pid, FLASHCACHE_WHITELIST);
		return 0;
	case FLASHCACHEDELALLWHITELIST:
		flashcache_del_all_pids(dmc, FLASHCACHE_WHITELIST, 0);
		return 0;
	default:
		fake_file.f_mode = dmc->disk_dev->mode;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
		fake_file.f_dentry = &fake_dentry;
#else
		fake_file.f_path.dentry = &fake_dentry;
#endif
		fake_dentry.d_inode = bdev->bd_inode;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,27)
		return blkdev_driver_ioctl(bdev->bd_inode, &fake_file, bdev->bd_disk, cmd, arg);
#else
		return __blkdev_driver_ioctl(dmc->disk_dev->bdev, dmc->disk_dev->mode, cmd, arg);
#endif
	}

}
