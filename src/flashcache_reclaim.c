/****************************************************************************
 *  flashcache_reclaim.c
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
#include <linux/sort.h>
#include <linux/time.h>
#include <asm/kmap_types.h>

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

static void flashcache_reclaim_remove_block_from_list(struct cache_c *dmc, int index);
static void flashcache_reclaim_add_block_to_list_mru(struct cache_c *dmc, int index);
static void flashcache_reclaim_add_block_to_list_lru(struct cache_c *dmc, int index);
static int flashcache_reclaim_demote_block(struct cache_c *dmc, int index);

/* Get least recently used FIFO block */
void
flashcache_reclaim_fifo_get_old_block(struct cache_c *dmc, int start_index, int *index)
{
	int set = start_index / dmc->assoc;
	struct cache_set *cache_set = &dmc->cache_sets[set];
	int end_index = start_index + dmc->assoc;
	int slots_searched = 0;
	int i;

	i = cache_set->set_fifo_next;
	while (slots_searched < dmc->assoc) {
		VERIFY(i >= start_index);
		VERIFY(i < end_index);
		if (dmc->cache[i].cache_state == VALID) {
			*index = i;
			VERIFY((dmc->cache[*index].cache_state & FALLOW_DOCLEAN) == 0);
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
	cache_set->set_fifo_next = i;
}

/* Rebalance the hot/warm LRU block sizing in each set */
void
flashcache_reclaim_rebalance_lru(struct cache_c *dmc, int new_lru_hot_pct)
{
	int new_hot_blocks, old_hot_blocks;
	int set, index;
	struct cache_set *cache_set;
	struct cacheblock *cacheblk;
	int blocks_to_move, moved;
	int start_index;
	
	if (new_lru_hot_pct > 100 || new_lru_hot_pct < 0)
		return;
	new_hot_blocks = (dmc->assoc * new_lru_hot_pct) / 100;
	old_hot_blocks = (dmc->assoc * atomic_read(&dmc->hot_list_pct)) / 100;
	if (new_hot_blocks > old_hot_blocks) {
		/* Move the requisite blocks from warm list -> hot list for each set */
		blocks_to_move = new_hot_blocks - old_hot_blocks;
		for (set = 0 ; set < (dmc->size >> dmc->assoc_shift) ; set++) {
			start_index = set * dmc->assoc;
			cache_set = &dmc->cache_sets[set];
			spin_lock_irq(&cache_set->set_spin_lock);
			moved = 0;
			while ((cache_set->warmlist_lru_head != FLASHCACHE_NULL) &&
			       (moved < blocks_to_move)) {
				index = cache_set->warmlist_lru_head + start_index;
				flashcache_reclaim_remove_block_from_list(dmc, index);
				cacheblk = &dmc->cache[index];
				cacheblk->lru_state &= ~LRU_WARM;
				cacheblk->lru_state |= LRU_HOT;
				cacheblk->use_cnt = 0;
				flashcache_reclaim_add_block_to_list_lru(dmc, index);
				moved++;
			}
			spin_unlock_irq(&cache_set->set_spin_lock);
		}
	} else {
		/* Move the requisite blocks from hot list -> warm list */
		blocks_to_move = old_hot_blocks - new_hot_blocks;
		for (set = 0 ; set < (dmc->size >> dmc->assoc_shift) ; set++) {
			start_index = set * dmc->assoc;
			cache_set = &dmc->cache_sets[set];
			spin_lock_irq(&cache_set->set_spin_lock);
			moved = 0;
			while ((cache_set->hotlist_lru_head != FLASHCACHE_NULL) &&
			       (moved < blocks_to_move)) {
				index = cache_set->hotlist_lru_head + start_index;
				flashcache_reclaim_remove_block_from_list(dmc, index);
				cacheblk = &dmc->cache[index];
				cacheblk->lru_state &= ~LRU_HOT;
				cacheblk->lru_state |= LRU_WARM;
				cacheblk->use_cnt = 0;
				flashcache_reclaim_add_block_to_list_lru(dmc,index);
				moved++;
			}
			spin_unlock_irq(&cache_set->set_spin_lock);
		}
	}
	atomic_set(&dmc->hot_list_pct, new_lru_hot_pct);
}

/* For each set, split available blocks into the 2 LRU Queues */
void
flashcache_reclaim_init_lru_lists(struct cache_c *dmc)
{
	int hot_blocks_set;
	int set, j, block_index;
	struct cache_set *cache_set;
	int start_index;
	struct cacheblock *cacheblk;

	hot_blocks_set = (dmc->assoc * atomic_read(&dmc->hot_list_pct)) / 100;
	for (set = 0 ; set < (dmc->size >> dmc->assoc_shift) ; set++) {
		cache_set = &dmc->cache_sets[set];
		spin_lock_irq(&cache_set->set_spin_lock);
		start_index = set * dmc->assoc;
		for (j = 0 ; j < hot_blocks_set ; j++) {
			block_index = start_index + j;
			cacheblk = &dmc->cache[block_index];
			cacheblk->lru_prev = FLASHCACHE_NULL;
			cacheblk->lru_next = FLASHCACHE_NULL;
			cacheblk->lru_state = LRU_HOT;
			flashcache_reclaim_add_block_to_list_lru(dmc, block_index);
		}
		for ( ; j < dmc->assoc; j++) {
			block_index = start_index + j;
			cacheblk = &dmc->cache[block_index];
			cacheblk->lru_prev = cacheblk->lru_next = FLASHCACHE_NULL;
			cacheblk->lru_state = LRU_WARM;
			flashcache_reclaim_add_block_to_list_lru(dmc, block_index);
		}
		spin_unlock_irq(&cache_set->set_spin_lock);
	}
}

/* Removes a block from its list */
static void
flashcache_reclaim_remove_block_from_list(struct cache_c *dmc, int index)
{
	int set = index / dmc->assoc;
	int start_index = set * dmc->assoc;
	struct cacheblock *cacheblk = &dmc->cache[index];
	struct cache_set *cache_set = &dmc->cache_sets[set];

	/* At least one should be set */
	VERIFY((cacheblk->lru_state & (LRU_WARM | LRU_HOT)) != 0);
	/* Both should not be set */
	VERIFY((cacheblk->lru_state & (LRU_WARM | LRU_HOT)) != (LRU_HOT | LRU_WARM));
	if (unlikely((cacheblk->lru_prev == FLASHCACHE_NULL) && 
		     (cacheblk->lru_next == FLASHCACHE_NULL))) {
		/* 
		 * Is this the only member on the list ? Or is this not on the list 
		 * at all ?
		 */
		if (cacheblk->lru_state & LRU_WARM) {
			if (cache_set->warmlist_lru_head == FLASHCACHE_NULL &&
			    cache_set->warmlist_lru_tail == FLASHCACHE_NULL)
				return;
		} else {
			if (cache_set->hotlist_lru_head == FLASHCACHE_NULL &&
			    cache_set->hotlist_lru_tail == FLASHCACHE_NULL)
				return;			
		}
	}
	if (cacheblk->lru_prev != FLASHCACHE_NULL)
		dmc->cache[cacheblk->lru_prev + start_index].lru_next = 
			cacheblk->lru_next;
	else {
		if (cacheblk->lru_state & LRU_WARM)
			cache_set->warmlist_lru_head = cacheblk->lru_next;
		else
			cache_set->hotlist_lru_head = cacheblk->lru_next;
	}
	if (cacheblk->lru_next != FLASHCACHE_NULL)
		dmc->cache[cacheblk->lru_next + start_index].lru_prev = 
			cacheblk->lru_prev;
	else {
		if (cacheblk->lru_state & LRU_WARM)
			cache_set->warmlist_lru_tail = cacheblk->lru_prev;
		else
			cache_set->hotlist_lru_tail = cacheblk->lru_prev;
	}
	if (cacheblk->lru_state & LRU_WARM) {
		dmc->lru_warm_blocks--;
		cache_set->lru_warm_blocks--;
		if (cache_set->lru_warm_blocks == 0) {
			VERIFY(cache_set->warmlist_lru_head == FLASHCACHE_NULL);
			VERIFY(cache_set->warmlist_lru_tail == FLASHCACHE_NULL);
		}
		if (cache_set->warmlist_lru_head != FLASHCACHE_NULL)
			VERIFY(cache_set->lru_warm_blocks > 0);
		if (cache_set->warmlist_lru_tail != FLASHCACHE_NULL)
			VERIFY(cache_set->lru_warm_blocks > 0);		
	} else {
		dmc->lru_hot_blocks--;
		cache_set->lru_hot_blocks--;
		if (cache_set->lru_hot_blocks == 0) {
			VERIFY(cache_set->hotlist_lru_head == FLASHCACHE_NULL);
			VERIFY(cache_set->hotlist_lru_tail == FLASHCACHE_NULL);
		}
		if (cache_set->hotlist_lru_head != FLASHCACHE_NULL)
			VERIFY(cache_set->lru_hot_blocks > 0);
		if (cache_set->hotlist_lru_tail != FLASHCACHE_NULL)
			VERIFY(cache_set->lru_hot_blocks > 0);		
	}
}

/* Adds a block to the MRU position of its list */
static void
flashcache_reclaim_add_block_to_list_mru(struct cache_c *dmc, int index)
{
	int set = index / dmc->assoc;
	int start_index = set * dmc->assoc;
	int my_index = index - start_index;
	struct cacheblock *cacheblk = &dmc->cache[index];
	struct cache_set *cache_set = &dmc->cache_sets[set];

	/* At least one should be set */
	VERIFY((cacheblk->lru_state & (LRU_WARM | LRU_HOT)) != 0);
	/* Both should not be set */
	VERIFY((cacheblk->lru_state & (LRU_WARM | LRU_HOT)) != (LRU_HOT | LRU_WARM));
	cacheblk->lru_next = FLASHCACHE_NULL;
	if (cacheblk->lru_state & LRU_WARM) {
		cacheblk->lru_prev = cache_set->warmlist_lru_tail;
		if (cache_set->warmlist_lru_tail == FLASHCACHE_NULL)
			cache_set->warmlist_lru_head = my_index;
		else
			dmc->cache[cache_set->warmlist_lru_tail + start_index].lru_next = 
				my_index;
		cache_set->warmlist_lru_tail = my_index;
	} else {
		cacheblk->lru_prev = cache_set->hotlist_lru_tail;
		if (cache_set->hotlist_lru_tail == FLASHCACHE_NULL)
			cache_set->hotlist_lru_head = my_index;
		else
			dmc->cache[cache_set->hotlist_lru_tail + start_index].lru_next = 
				my_index;
		cache_set->hotlist_lru_tail = my_index;
	}
	if (cacheblk->lru_state & LRU_WARM) {
		dmc->lru_warm_blocks++;
		cache_set->lru_warm_blocks++;
	} else {
		dmc->lru_hot_blocks++;		
		cache_set->lru_hot_blocks++;
	}
}

/* Adds a block to the LRU position of its list */
static void
flashcache_reclaim_add_block_to_list_lru(struct cache_c *dmc, int index)
{
	int set = index / dmc->assoc;
	int start_index = set * dmc->assoc;
	int my_index = index - start_index;
	struct cacheblock *cacheblk = &dmc->cache[index];
	struct cache_set *cache_set = &dmc->cache_sets[set];

	/* At least one should be set */
	VERIFY((cacheblk->lru_state & (LRU_WARM | LRU_HOT)) != 0);
	/* Both should not be set */
	VERIFY((cacheblk->lru_state & (LRU_WARM | LRU_HOT)) != (LRU_HOT | LRU_WARM));
	cacheblk->lru_prev = FLASHCACHE_NULL;
	if (cacheblk->lru_state & LRU_WARM) {
		cacheblk->lru_next = cache_set->warmlist_lru_head;
		if (cache_set->warmlist_lru_head == FLASHCACHE_NULL)
			cache_set->warmlist_lru_tail = my_index;
		else
			dmc->cache[cache_set->warmlist_lru_head + start_index].lru_prev = 
				my_index;
		cache_set->warmlist_lru_head = my_index;
	} else {
		cacheblk->lru_next = cache_set->hotlist_lru_head;
		if (cache_set->hotlist_lru_head == FLASHCACHE_NULL)
			cache_set->hotlist_lru_tail = my_index;
		else
			dmc->cache[cache_set->hotlist_lru_head + start_index].lru_prev = 
				my_index;
		cache_set->hotlist_lru_head = my_index;
	}
	if (cacheblk->lru_state & LRU_WARM) {
		cache_set->lru_warm_blocks++;
		dmc->lru_warm_blocks++;
	} else {
		cache_set->lru_hot_blocks++;
		dmc->lru_hot_blocks++;
	}
}

/* Move block to MRU position in the same list */
void
flashcache_reclaim_move_to_mru(struct cache_c *dmc, int index)
{
	struct cacheblock *cacheblk = &dmc->cache[index];

	/* At least one should be set */
	VERIFY((cacheblk->lru_state & (LRU_WARM | LRU_HOT)) != 0);
	/* Both should not be set */
	VERIFY((cacheblk->lru_state & (LRU_WARM | LRU_HOT)) != (LRU_HOT | LRU_WARM));
	/* Remove from its list */
	flashcache_reclaim_remove_block_from_list(dmc, index);
	/* And add it to LRU Tail (MRU side) of its list */
	flashcache_reclaim_add_block_to_list_mru(dmc, index);
}

/* Promote this warm block with the LRU block in the hot queue */
static int
flashcache_reclaim_promote_block(struct cache_c *dmc, int index)
{
	struct cacheblock *cacheblk = &dmc->cache[index];
	int hot_block;
	int set = index / dmc->assoc;
	int start_index = set * dmc->assoc;
	struct cache_set *cache_set = &dmc->cache_sets[set];

	VERIFY(cacheblk->lru_state & LRU_WARM);
	hot_block = cache_set->hotlist_lru_head;
	if (hot_block == FLASHCACHE_NULL)
		/* We cannot swap this block into the hot list */
		return 0;
	hot_block += start_index;
	/* Remove warm block from its list first */
	flashcache_reclaim_remove_block_from_list(dmc, index);
	/* Remove hot block identified above from its list */
	flashcache_reclaim_remove_block_from_list(dmc, hot_block);
	/* Swap the 2 blocks */
	cacheblk->lru_state &= ~LRU_WARM;
	cacheblk->lru_state |= LRU_HOT;
	cacheblk->use_cnt = 0;
	flashcache_reclaim_add_block_to_list_lru(dmc, index);
	cacheblk = &dmc->cache[hot_block];
	VERIFY(cacheblk->lru_state & LRU_HOT);
	cacheblk->lru_state &= ~LRU_HOT;
	cacheblk->lru_state |= LRU_WARM;
	cacheblk->use_cnt = 0;
	flashcache_reclaim_add_block_to_list_mru(dmc, hot_block);
	dmc->flashcache_stats.lru_promotions++;
	return 1;
}

/* Swap this hot block with the MRU block in the warm queue */
static int
flashcache_reclaim_demote_block(struct cache_c *dmc, int index)
{
	struct cacheblock *cacheblk = &dmc->cache[index];
	int warm_block;
	int set = index / dmc->assoc;
	struct cache_set *cache_set = &dmc->cache_sets[set];
	int start_index = set * dmc->assoc;

	VERIFY(cacheblk->lru_state & LRU_HOT);
	warm_block = cache_set->warmlist_lru_tail;
	if (warm_block == FLASHCACHE_NULL)
		/* We cannot swap this block into the warm list */
		return 0;
	warm_block += start_index;
	/* Remove hot block from its list first */
	flashcache_reclaim_remove_block_from_list(dmc, index);
	/* Remove warm block identified above from its list */
	flashcache_reclaim_remove_block_from_list(dmc, warm_block);
	/* Swap the 2 blocks */
	cacheblk->lru_state &= ~LRU_HOT;
	cacheblk->lru_state |= LRU_WARM;
	cacheblk->use_cnt = 0;
	flashcache_reclaim_add_block_to_list_mru(dmc, index);
	cacheblk = &dmc->cache[warm_block];
	VERIFY(cacheblk->lru_state & LRU_WARM);
	cacheblk->lru_state &= ~LRU_WARM;
	cacheblk->lru_state |= LRU_HOT;
	cacheblk->use_cnt = 0;
	flashcache_reclaim_add_block_to_list_lru(dmc, warm_block);
	dmc->flashcache_stats.lru_demotions++;
	return 1;
}

/* 
 * Get least recently used LRU block
 * 
 * Algorithm :
 * 	Always pick block from the LRU end of the warm list.
 * 	And move it to the MRU end of the warm list.
 * 	If we don't find a suitable block in the "warm" list,
 * 	pick the block from the hot list, demote it to the warm
 *	list and move a block from the warm list to the hot list.
 */
void
flashcache_reclaim_lru_get_old_block(struct cache_c *dmc, int start_index, int *index)
{
	int lru_rel_index;
	struct cacheblock *cacheblk;
	int set = start_index / dmc->assoc;
	struct cache_set *cache_set = &dmc->cache_sets[set];

	*index = -1;
	lru_rel_index = cache_set->warmlist_lru_head;
	while (lru_rel_index != FLASHCACHE_NULL) {
		cacheblk = &dmc->cache[lru_rel_index + start_index];
		if (cacheblk->cache_state == VALID) {
			*index = cacheblk - &dmc->cache[0];
			VERIFY((cacheblk->cache_state & FALLOW_DOCLEAN) == 0);
			VERIFY(cacheblk->lru_state & LRU_WARM);
			VERIFY((cacheblk->lru_state & LRU_HOT) == 0);
			cacheblk->use_cnt = 0;
			flashcache_reclaim_move_to_mru(dmc, *index);
			break;
		}
		lru_rel_index = cacheblk->lru_next;
	}
	if (likely(*index != -1))
		return;
	/* 
	 * We did not find a block on the "warm" LRU list that we could take, pick 
	 * a block from the "hot" LRU list.
	 */
	lru_rel_index = cache_set->hotlist_lru_head;
	while (lru_rel_index != FLASHCACHE_NULL) {
		cacheblk = &dmc->cache[lru_rel_index + start_index];
		if (cacheblk->cache_state == VALID) {
			*index = cacheblk - &dmc->cache[0];
			VERIFY((cacheblk->cache_state & FALLOW_DOCLEAN) == 0);
			VERIFY(cacheblk->lru_state & LRU_HOT);
			VERIFY((cacheblk->lru_state & LRU_WARM) == 0);
			VERIFY(cacheblk->use_cnt == 0);
			/* 
			 * Swap this block with the MRU block in the warm list.
			 * To maintain equilibrium between the lists
			 * 1) We put this block in the MRU position on the warm list
			 * 2) Remove the block in the LRU position on the warm list and
			 * 3) Move that block to the LRU position on the hot list.
			 */
			if (!flashcache_reclaim_demote_block(dmc, *index))
				/* 
				 * We cannot demote this block to the warm list
				 * just move it to the MRU position.
				 */
				flashcache_reclaim_move_to_mru(dmc, *index);
			break;
		}
		lru_rel_index = cacheblk->lru_next;
	}
}

/* Block moved from warm to hot list on second access */

/* 
 * Block is accessed.
 * 
 * Algorithm :
   if (block is in the warm list) {
       block_lru_refcnt++;
       if (block_lru_refcnt >= THRESHOLD) {
          clear refcnt
          Swap this block for the block at LRU end of hot list
       } else 	  
          move it to MRU end of the warm list
   }
   if (block is in the hot list)
       move it to MRU end of the hot list
 */
void
flashcache_lru_accessed(struct cache_c *dmc, int index)
{
	struct cacheblock *cacheblk = &dmc->cache[index];

	if (cacheblk->lru_state & LRU_HOT)
		flashcache_reclaim_move_to_mru(dmc, index);
	else {
		/*
		 * If INVALID and on the warm list, just move it to the MRU
		 * position and leave it there. If haven't hit the use count
		 * threshold, move it to the MRU position and leave it there.
		 */
		VERIFY(cacheblk->lru_state & LRU_WARM);
		if (cacheblk->cache_state == INVALID ||
		    ++cacheblk->use_cnt < dmc->sysctl_lru_promote_thresh) {
			flashcache_reclaim_move_to_mru(dmc, index);
			return;
		}
		/* 
		 * Promote block to hot list. Swapping it with a block there.
		 * 
		 * Swap this block with the LRU block in the hot list.
		 * To maintain equilibrium between the lists
		 * 1) We put this block in the LRU position on the hot list
		 * 2) Remove the block in the LRU position on the hot list and
		 * 3) Move that block to the MRU position on the warm list.
		 */
		if (!flashcache_reclaim_promote_block(dmc, index))
			/* Could not promote block, move it to mru on warm list */
			flashcache_reclaim_move_to_mru(dmc, index);
	}
}
