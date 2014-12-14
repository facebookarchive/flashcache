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

static int fallow_clean_speed_min = FALLOW_SPEED_MIN;
static int fallow_clean_speed_max = FALLOW_SPEED_MAX;

extern u_int64_t size_hist[];

static char *flashcache_cons_procfs_cachename(struct cache_c *dmc, char *path_component);
static char *flashcache_cons_sysctl_devname(struct cache_c *dmc);

#define FLASHCACHE_PROC_ROOTDIR_NAME	"flashcache"

static int
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
flashcache_io_latency_init(struct ctl_table *table, int write,
			   void __user *buffer,
			   size_t *length, loff_t *ppos)
#else
flashcache_io_latency_init(ctl_table *table, int write,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
			   struct file *file,
#endif
			   void __user *buffer,
			   size_t *length, loff_t *ppos)
#endif
{
	struct cache_c *dmc = (struct cache_c *)table->extra1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
	proc_dointvec(table, write, file, buffer, length, ppos);
#else
	proc_dointvec(table, write, buffer, length, ppos);
#endif
	if (write) {
		if (dmc->sysctl_io_latency_hist) {
			int i;
				
			for (i = 0 ; i < IO_LATENCY_BUCKETS ; i++)
				dmc->latency_hist[i] = 0;
			dmc->latency_hist_10ms = 0;
		}
	}
	return 0;
}

static int 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
flashcache_sync_sysctl(struct ctl_table *table, int write,
		       void __user *buffer, 
		       size_t *length, loff_t *ppos)
#else
flashcache_sync_sysctl(ctl_table *table, int write,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
		       struct file *file, 
#endif
		       void __user *buffer, 
		       size_t *length, loff_t *ppos)
#endif
{
	struct cache_c *dmc = (struct cache_c *)table->extra1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
	proc_dointvec(table, write, file, buffer, length, ppos);
#else
	proc_dointvec(table, write, buffer, length, ppos);
#endif
	if (write) {
		if (dmc->sysctl_do_sync) {
			dmc->sysctl_stop_sync = 0;
			cancel_delayed_work(&dmc->delayed_clean);
			flush_scheduled_work();
			flashcache_sync_all(dmc);
		}
	}
	return 0;
}

static int 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
flashcache_zerostats_sysctl(struct ctl_table *table, int write,
			    void __user *buffer, 
			    size_t *length, loff_t *ppos)
#else
flashcache_zerostats_sysctl(ctl_table *table, int write,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
			    struct file *file, 
#endif
			    void __user *buffer, 
			    size_t *length, loff_t *ppos)
#endif
{
	struct cache_c *dmc = (struct cache_c *)table->extra1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
	proc_dointvec(table, write, file, buffer, length, ppos);
#else
	proc_dointvec(table, write, buffer, length, ppos);
#endif
	if (write) {
		if (dmc->sysctl_zerostats) {
			int i;

			memset(&dmc->flashcache_stats, 0, sizeof(struct flashcache_stats));
			for (i = 0 ; i < IO_LATENCY_BUCKETS ; i++)
				dmc->latency_hist[i] = 0;
			dmc->latency_hist_10ms = 0;
		}
	}
	return 0;
}

static int 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
flashcache_fallow_clean_speed_sysctl(struct ctl_table *table, int write,
				     void __user *buffer, 
				     size_t *length, loff_t *ppos)
#else
flashcache_fallow_clean_speed_sysctl(ctl_table *table, int write,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
				     struct file *file, 
#endif
				     void __user *buffer, 
				     size_t *length, loff_t *ppos)
#endif
{
	struct cache_c *dmc = (struct cache_c *)table->extra1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
	proc_dointvec(table, write, file, buffer, length, ppos);
#else
	proc_dointvec(table, write, buffer, length, ppos);
#endif
	if (write) {
		if (dmc->sysctl_fallow_clean_speed < fallow_clean_speed_min)
			dmc->sysctl_fallow_clean_speed = fallow_clean_speed_min;

		if (dmc->sysctl_fallow_clean_speed > fallow_clean_speed_max)
			dmc->sysctl_fallow_clean_speed = fallow_clean_speed_max;
	}
	return 0;
}

static int
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
flashcache_dirty_thresh_sysctl(struct ctl_table *table, int write,
			       void __user *buffer, 
			       size_t *length, loff_t *ppos)
#else
flashcache_dirty_thresh_sysctl(ctl_table *table, int write,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
			       struct file *file, 
#endif
			       void __user *buffer, 
			       size_t *length, loff_t *ppos)
#endif
{
	struct cache_c *dmc = (struct cache_c *)table->extra1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
        proc_dointvec(table, write, file, buffer, length, ppos);
#else
        proc_dointvec(table, write, buffer, length, ppos);
#endif
	if (write) {
		if (dmc->sysctl_dirty_thresh > DIRTY_THRESH_MAX)
			dmc->sysctl_dirty_thresh = DIRTY_THRESH_MAX;

		if (dmc->sysctl_dirty_thresh < DIRTY_THRESH_MIN)
			dmc->sysctl_dirty_thresh = DIRTY_THRESH_MIN;

		dmc->dirty_thresh_set = 
			(dmc->assoc * dmc->sysctl_dirty_thresh) / 100;
	}
	return 0;
}

static int
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
flashcache_lru_hot_pct_sysctl(struct ctl_table *table, int write,
			      void __user *buffer, 
			      size_t *length, loff_t *ppos)
#else
flashcache_lru_hot_pct_sysctl(ctl_table *table, int write,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
			       struct file *file, 
#endif
			       void __user *buffer, 
			       size_t *length, loff_t *ppos)
#endif
{
	struct cache_c *dmc = (struct cache_c *)table->extra1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
        proc_dointvec(table, write, file, buffer, length, ppos);
#else
        proc_dointvec(table, write, buffer, length, ppos);
#endif
	if (write)
		flashcache_reclaim_rebalance_lru(dmc, dmc->sysctl_lru_hot_pct);
	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#define CTL_UNNUMBERED			-2
#endif

/*
 * Each ctl_table array needs to be 1 more than the actual number of
 * entries - zero padded at the end ! Therefore the NUM_*_SYSCTLS
 * is 1 more than then number of sysctls.
 */
#define FLASHCACHE_NUM_WRITEBACK_SYSCTLS	22

static struct flashcache_writeback_sysctl_table {
	struct ctl_table_header *sysctl_header;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
	struct ctl_table	vars[FLASHCACHE_NUM_WRITEBACK_SYSCTLS];
	struct ctl_table	dev[2];
	struct ctl_table	dir[2];
	struct ctl_table	root[2];
#else
	ctl_table		vars[FLASHCACHE_NUM_WRITEBACK_SYSCTLS];
	ctl_table		dev[2];
	ctl_table		dir[2];
	ctl_table		root[2];
#endif
} flashcache_writeback_sysctl = {
	.vars = {
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "io_latency_hist",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &flashcache_io_latency_init,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.strategy	= &sysctl_intvec,
#endif
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "do_sync",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &flashcache_sync_sysctl,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.strategy	= &sysctl_intvec,
#endif
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "stop_sync",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "dirty_thresh_pct",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &flashcache_dirty_thresh_sysctl,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.strategy	= &sysctl_intvec,
#endif
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "max_clean_ios_total",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "max_clean_ios_set",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "do_pid_expiry",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "max_pids",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "pid_expiry_secs",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "reclaim_policy",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "zero_stats",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &flashcache_zerostats_sysctl,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.strategy	= &sysctl_intvec,
#endif
		},
#ifdef notdef
		/* 
		 * Disable this for all except devel builds 
		 * If you enable this, you must bump FLASHCACHE_NUM_WRITEBACK_SYSCTLS
		 * by 1 !
		 */
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "error_inject",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
#endif
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "fast_remove",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "cache_all",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "fallow_clean_speed",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &flashcache_fallow_clean_speed_sysctl,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.strategy	= &sysctl_intvec,
#endif
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "fallow_delay",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "skip_seq_thresh_kb",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "clean_on_read_miss",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "clean_on_write_miss",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "lru_promote_thresh",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "lru_hot_pct",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &flashcache_lru_hot_pct_sysctl,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.strategy	= &sysctl_intvec,
#endif
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "new_style_write_merge",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
	},
	.dev = {
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "flashcache-dev",
			.maxlen		= 0,
			.mode		= S_IRUGO|S_IXUGO,
			.child		= flashcache_writeback_sysctl.vars,
		},
	},
	.dir = {
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= FLASHCACHE_PROC_ROOTDIR_NAME,
			.maxlen		= 0,
			.mode		= S_IRUGO|S_IXUGO,
			.child		= flashcache_writeback_sysctl.dev,
		},
	},
	.root = {
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_DEV,
#endif
			.procname	= "dev",
			.maxlen		= 0,
			.mode		= 0555,
			.child		= flashcache_writeback_sysctl.dir,
		},
	},
};

/*
 * Each ctl_table array needs to be 1 more than the actual number of
 * entries - zero padded at the end ! Therefore the NUM_*_SYSCTLS
 * is 1 more than then number of sysctls.
 */
#define FLASHCACHE_NUM_WRITETHROUGH_SYSCTLS	11

static struct flashcache_writethrough_sysctl_table {
	struct ctl_table_header *sysctl_header;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
	struct ctl_table	vars[FLASHCACHE_NUM_WRITETHROUGH_SYSCTLS];
	struct ctl_table	dev[2];
	struct ctl_table	dir[2];
	struct ctl_table	root[2];
#else
	ctl_table		vars[FLASHCACHE_NUM_WRITETHROUGH_SYSCTLS];
	ctl_table		dev[2];
	ctl_table		dir[2];
	ctl_table		root[2];
#endif
} flashcache_writethrough_sysctl = {
	.vars = {
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "io_latency_hist",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &flashcache_io_latency_init,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.strategy	= &sysctl_intvec,
#endif
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "do_pid_expiry",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "max_pids",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "pid_expiry_secs",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "reclaim_policy",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "zero_stats",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &flashcache_zerostats_sysctl,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.strategy	= &sysctl_intvec,
#endif
		},
#ifdef notdef
		/* 
		 * Disable this for all except devel builds 
		 * If you enable this, you must bump FLASHCACHE_NUM_WRITEBACK_SYSCTLS
		 * by 1 !
		 */
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "error_inject",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
#endif
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "cache_all",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "skip_seq_thresh_kb",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "lru_promote_thresh",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &proc_dointvec,
		},
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "lru_hot_pct",
			.maxlen		= sizeof(int),
			.mode		= 0644,
			.proc_handler	= &flashcache_lru_hot_pct_sysctl,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.strategy	= &sysctl_intvec,
#endif
		},
	},
	.dev = {
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= "flashcache-dev",
			.maxlen		= 0,
			.mode		= S_IRUGO|S_IXUGO,
			.child		= flashcache_writethrough_sysctl.vars,
		},
	},
	.dir = {
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_UNNUMBERED,
#endif
			.procname	= FLASHCACHE_PROC_ROOTDIR_NAME,
			.maxlen		= 0,
			.mode		= S_IRUGO|S_IXUGO,
			.child		= flashcache_writethrough_sysctl.dev,
		},
	},
	.root = {
		{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			.ctl_name	= CTL_DEV,
#endif
			.procname	= "dev",
			.maxlen		= 0,
			.mode		= 0555,
			.child		= flashcache_writethrough_sysctl.dir,
		},
	},
};

int *
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
flashcache_find_sysctl_data(struct cache_c *dmc, struct ctl_table *vars)
#else
flashcache_find_sysctl_data(struct cache_c *dmc, ctl_table *vars)
#endif
{
	if (strcmp(vars->procname, "io_latency_hist") == 0)
		return &dmc->sysctl_io_latency_hist;
	else if (strcmp(vars->procname, "do_sync") == 0)
		return &dmc->sysctl_do_sync;
	else if (strcmp(vars->procname, "stop_sync") == 0)
		return &dmc->sysctl_stop_sync;
	else if (strcmp(vars->procname, "dirty_thresh_pct") == 0) 
		return &dmc->sysctl_dirty_thresh;
	else if (strcmp(vars->procname, "max_clean_ios_total") == 0) 
		return &dmc->max_clean_ios_total;
	else if (strcmp(vars->procname, "max_clean_ios_set") == 0) 
		return &dmc->max_clean_ios_set;
	else if (strcmp(vars->procname, "do_pid_expiry") == 0) 
		return &dmc->sysctl_pid_do_expiry;
	else if (strcmp(vars->procname, "max_pids") == 0) 
		return &dmc->sysctl_max_pids;
	else if (strcmp(vars->procname, "pid_expiry_secs") == 0) 
		return &dmc->sysctl_pid_expiry_secs;
	else if (strcmp(vars->procname, "reclaim_policy") == 0) 
		return &dmc->sysctl_reclaim_policy;
	else if (strcmp(vars->procname, "zero_stats") == 0) 
		return &dmc->sysctl_zerostats;
	else if (strcmp(vars->procname, "error_inject") == 0) 
		return &dmc->sysctl_error_inject;
	else if (strcmp(vars->procname, "fast_remove") == 0) 
		return &dmc->sysctl_fast_remove;
	else if (strcmp(vars->procname, "cache_all") == 0) 
		return &dmc->sysctl_cache_all;
	else if (strcmp(vars->procname, "fallow_clean_speed") == 0) 
		return &dmc->sysctl_fallow_clean_speed;
	else if (strcmp(vars->procname, "fallow_delay") == 0) 
		return &dmc->sysctl_fallow_delay;
	else if (strcmp(vars->procname, "skip_seq_thresh_kb") == 0) 
		return &dmc->sysctl_skip_seq_thresh_kb;
	else if (strcmp(vars->procname, "clean_on_read_miss") == 0) 
		return &dmc->sysctl_clean_on_read_miss;
	else if (strcmp(vars->procname, "clean_on_write_miss") == 0) 
		return &dmc->sysctl_clean_on_write_miss;
	else if (strcmp(vars->procname, "lru_promote_thresh") == 0) 
		return &dmc->sysctl_lru_promote_thresh;
	else if (strcmp(vars->procname, "lru_hot_pct") == 0)
		return &dmc->sysctl_lru_hot_pct;
	else if (strcmp(vars->procname, "new_style_write_merge") == 0)
		return &dmc->sysctl_new_style_write_merge;
	printk(KERN_ERR "flashcache_find_sysctl_data: Unknown sysctl %s\n", vars->procname);
	panic("flashcache_find_sysctl_data: Unknown sysctl %s\n", vars->procname);
	return NULL;
}

static void
flashcache_writeback_sysctl_register(struct cache_c *dmc)
{
	int i;
	struct flashcache_writeback_sysctl_table *t;
	
	t = kmemdup(&flashcache_writeback_sysctl, sizeof(*t), GFP_KERNEL);
	if (t == NULL)
		return;
	for (i = 0 ; i < ARRAY_SIZE(t->vars) - 1 ; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
		t->vars[i].de = NULL;
#endif
		t->vars[i].data = flashcache_find_sysctl_data(dmc, &t->vars[i]);
		t->vars[i].extra1 = dmc;
	}
	
	t->dev[0].procname = flashcache_cons_sysctl_devname(dmc);
	t->dev[0].child = t->vars;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
	t->dev[0].de = NULL;
#endif
	t->dir[0].child = t->dev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
	t->dir[0].de = NULL;
#endif
	t->root[0].child = t->dir;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
	t->root[0].de = NULL;
#endif
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
	t->sysctl_header = register_sysctl_table(t->root, 0);
#else
	t->sysctl_header = register_sysctl_table(t->root);
#endif
	if (t->sysctl_header == NULL)
		goto out;
	
	dmc->sysctl_handle = t;
	return;

out:
	kfree(t->dev[0].procname);
	kfree(t);
}

static void
flashcache_writeback_sysctl_unregister(struct cache_c *dmc)
{
	struct flashcache_writeback_sysctl_table *t;

	t = dmc->sysctl_handle;
	if (t != NULL) {
		dmc->sysctl_handle = NULL;
		unregister_sysctl_table(t->sysctl_header);
		kfree(t->dev[0].procname);
		kfree(t);		
	}
}

static void
flashcache_writethrough_sysctl_register(struct cache_c *dmc)
{
	int i;
	struct flashcache_writethrough_sysctl_table *t;
	
	t = kmemdup(&flashcache_writethrough_sysctl, sizeof(*t), GFP_KERNEL);
	if (t == NULL)
		return;
	for (i = 0 ; i < ARRAY_SIZE(t->vars) - 1 ; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
		t->vars[i].de = NULL;
#endif
		t->vars[i].data = flashcache_find_sysctl_data(dmc, &t->vars[i]);
		t->vars[i].extra1 = dmc;
	}
	
	t->dev[0].procname = flashcache_cons_sysctl_devname(dmc);
	t->dev[0].child = t->vars;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
	t->dev[0].de = NULL;
#endif
	t->dir[0].child = t->dev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
	t->dir[0].de = NULL;
#endif
	t->root[0].child = t->dir;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
	t->root[0].de = NULL;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
	t->sysctl_header = register_sysctl_table(t->root, 0);
#else
	t->sysctl_header = register_sysctl_table(t->root);
#endif
	if (t->sysctl_header == NULL)
		goto out;
	
	dmc->sysctl_handle = t;
	return;

out:
	kfree(t->dev[0].procname);
	kfree(t);
}

static void
flashcache_writethrough_sysctl_unregister(struct cache_c *dmc)
{
	struct flashcache_writethrough_sysctl_table *t;

	t = dmc->sysctl_handle;
	if (t != NULL) {
		dmc->sysctl_handle = NULL;
		unregister_sysctl_table(t->sysctl_header);
		kfree(t->dev[0].procname);
		kfree(t);		
	}
}


static int 
flashcache_stats_show(struct seq_file *seq, void *v)
{
	struct cache_c *dmc = seq->private;
	struct flashcache_stats *stats;
	int read_hit_pct, write_hit_pct, dirty_write_hit_pct;

	stats = &dmc->flashcache_stats;
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
	seq_printf(seq, "reads=%lu writes=%lu \n", 
		   stats->reads, stats->writes);
	seq_printf(seq, "read_hits=%lu read_hit_percent=%d ", 
		   stats->read_hits, read_hit_pct);
	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK || dmc->cache_mode == FLASHCACHE_WRITE_THROUGH) {
		seq_printf(seq, "write_hits=%lu write_hit_percent=%d ", 
		   	   stats->write_hits, write_hit_pct);
	}
	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) {
		seq_printf(seq, "dirty_write_hits=%lu dirty_write_hit_percent=%d ",
			   stats->dirty_write_hits, dirty_write_hit_pct);
	}
	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK || dmc->cache_mode == FLASHCACHE_WRITE_THROUGH) {
		seq_printf(seq, "replacement=%lu write_replacement=%lu ",
			   stats->replace, stats->wr_replace);
		seq_printf(seq,  "write_invalidates=%lu read_invalidates=%lu ",
			   stats->wr_invalidates, stats->rd_invalidates);
	} else {	/* WRITE_AROUND */
		seq_printf(seq, "replacement=%lu ",
			   stats->replace);
		seq_printf(seq, "read_invalidates=%lu ",
			   stats->rd_invalidates);
	}
#ifdef FLASHCACHE_DO_CHECKSUMS
	seq_printf(seq,  "checksum_store=%ld checksum_valid=%ld checksum_invalid=%ld ",
		stats->checksum_store, stats->checksum_valid, stats->checksum_invalid);
#endif
	seq_printf(seq,  "pending_enqueues=%lu pending_inval=%lu ",
		   stats->enqueues, stats->pending_inval);

	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) { 
		seq_printf(seq, "metadata_dirties=%lu metadata_cleans=%lu ",
			   stats->md_write_dirty, stats->md_write_clean);
		seq_printf(seq, "metadata_batch=%lu metadata_ssd_writes=%lu ",
			   stats->md_write_batch, stats->md_ssd_writes);
		seq_printf(seq, "cleanings=%lu fallow_cleanings=%lu ",
			   stats->cleanings, stats->fallow_cleanings);
	}
	seq_printf(seq, "no_room=%lu ",
		   stats->noroom);

	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK) {
 		seq_printf(seq, "front_merge=%lu back_merge=%lu ",
			   stats->front_merge, stats->back_merge);
	}
	seq_printf(seq,  "disk_reads=%lu disk_writes=%lu ssd_reads=%lu ssd_writes=%lu ",
		   stats->disk_reads, stats->disk_writes, stats->ssd_reads, stats->ssd_writes);
	seq_printf(seq,  "uncached_reads=%lu uncached_writes=%lu uncached_IO_requeue=%lu ",
		   stats->uncached_reads, stats->uncached_writes, stats->uncached_io_requeue);
	seq_printf(seq,  "uncached_sequential_reads=%lu uncached_sequential_writes=%lu ",
		   stats->uncached_sequential_reads, stats->uncached_sequential_writes);
	seq_printf(seq, "pid_adds=%lu pid_dels=%lu pid_drops=%lu pid_expiry=%lu\n",
		   stats->pid_adds, stats->pid_dels, stats->pid_drops, stats->expiry);
	return 0;
}

static int 
flashcache_stats_open(struct inode *inode, struct file *file)
{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		return single_open(file, &flashcache_stats_show, PDE(inode)->data);	
	#endif
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		return single_open(file, &flashcache_stats_show, PDE_DATA(inode));
	#endif
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
	struct cache_c *dmc = seq->private;

	seq_printf(seq, "disk_read_errors=%d disk_write_errors=%d ",
		   dmc->flashcache_errors.disk_read_errors, 
		   dmc->flashcache_errors.disk_write_errors);
	seq_printf(seq, "ssd_read_errors=%d ssd_write_errors=%d ",
		   dmc->flashcache_errors.ssd_read_errors, 
		   dmc->flashcache_errors.ssd_write_errors);
	seq_printf(seq, "memory_alloc_errors=%d\n", 
		   dmc->flashcache_errors.memory_alloc_errors);
	return 0;
}

static int 
flashcache_errors_open(struct inode *inode, struct file *file)
{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		return single_open(file, &flashcache_errors_show, PDE(inode)->data);	
	#endif
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		return single_open(file, &flashcache_errors_show, PDE_DATA(inode));
	#endif
}

static struct file_operations flashcache_errors_operations = {
	.open		= flashcache_errors_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int 
flashcache_iosize_hist_show(struct seq_file *seq, void *v)
{
	int i;
	
	for (i = 1 ; i <= 32 ; i++) {
		seq_printf(seq, "%d:%llu ", i*512, size_hist[i]);
	}
	seq_printf(seq, "\n");
	return 0;
}

static int 
flashcache_iosize_hist_open(struct inode *inode, struct file *file)
{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		return single_open(file, &flashcache_iosize_hist_show, PDE(inode)->data);
	#endif
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		return single_open(file, &flashcache_iosize_hist_show, PDE_DATA(inode));
	#endif
}

static struct file_operations flashcache_iosize_hist_operations = {
	.open		= flashcache_iosize_hist_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int 
flashcache_pidlists_show(struct seq_file *seq, void *v)
{
	struct cache_c *dmc = seq->private;
	struct flashcache_cachectl_pid *pid_list;
	unsigned long flags;

	spin_lock_irqsave(&dmc->ioctl_lock, flags);
	seq_printf(seq, "Blacklist: ");
	pid_list = dmc->blacklist_head;
	while (pid_list != NULL) {
		seq_printf(seq, "%u ", pid_list->pid);
		pid_list = pid_list->next;
	}
	seq_printf(seq, "\n");
	seq_printf(seq, "Whitelist: ");
	pid_list = dmc->whitelist_head;
	while (pid_list != NULL) {
		seq_printf(seq, "%u ", pid_list->pid);
		pid_list = pid_list->next;
	}
	seq_printf(seq, "\n");
	spin_unlock_irqrestore(&dmc->ioctl_lock, flags);
	return 0;
}

static int 
flashcache_pidlists_open(struct inode *inode, struct file *file)
{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		return single_open(file, &flashcache_pidlists_show, PDE(inode)->data);	
	#endif
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		return single_open(file, &flashcache_pidlists_show, PDE_DATA(inode));
	#endif
}

static struct file_operations flashcache_pidlists_operations = {
	.open		= flashcache_pidlists_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

extern char *flashcache_sw_version;

static int 
flashcache_version_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "Flashcache Version : %s\n", flashcache_sw_version);
#ifdef COMMIT_REV
	seq_printf(seq, "git commit: %s\n", COMMIT_REV);
#endif
	return 0;
}

static int 
flashcache_version_open(struct inode *inode, struct file *file)
{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		return single_open(file, &flashcache_version_show, PDE(inode)->data);	
	#endif
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		return single_open(file, &flashcache_version_show, PDE_DATA(inode));
	#endif
}

static struct file_operations flashcache_version_operations = {
	.open		= flashcache_version_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

void
flashcache_module_procfs_init(void)
{
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *entry;

	if (proc_mkdir("flashcache", NULL)) {
		#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
			entry = create_proc_entry("flashcache/flashcache_version", 0, NULL);
			if (entry)
				entry->proc_fops =  &flashcache_version_operations;
		#endif
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
			entry = proc_create("flashcache/flashcache_version", 0, NULL, &flashcache_version_operations);
		#endif	

	}
#endif /* CONFIG_PROC_FS */
}

void
flashcache_module_procfs_release(void)
{
#ifdef CONFIG_PROC_FS
	(void)remove_proc_entry("flashcache/flashcache_version", NULL);
	(void)remove_proc_entry("flashcache", NULL);
#endif /* CONFIG_PROC_FS */
}

static char *
flashcache_cons_sysctl_devname(struct cache_c *dmc)
{
	char *pathname;
	
	pathname = kzalloc(strlen(dmc->cache_devname) + strlen(dmc->disk_devname) + 2,
			   GFP_KERNEL);
	strcpy(pathname, strrchr(dmc->cache_devname, '/') + 1);
	strcat(pathname, "+");
	strcat(pathname, strrchr(dmc->disk_devname, '/') + 1);
	return pathname;
}

static char *
flashcache_cons_procfs_cachename(struct cache_c *dmc, char *path_component)
{
	char *pathname;
	char *s;
	
	pathname = kzalloc(strlen(dmc->cache_devname) + strlen(dmc->disk_devname) + 4 + 
			   strlen(FLASHCACHE_PROC_ROOTDIR_NAME) + 
			   strlen(path_component), 
			   GFP_KERNEL);
	strcpy(pathname, FLASHCACHE_PROC_ROOTDIR_NAME);
	strcat(pathname, "/");
	s = strrchr(dmc->cache_devname, '/');
	if (s) 
		s++;
	else
		s = dmc->cache_devname;
	strcat(pathname, s);
	strcat(pathname, "+");
	s = strrchr(dmc->disk_devname, '/');
	if (s) 
		s++;
	else
		s = dmc->disk_devname;
	strcat(pathname, s);
	if (strcmp(path_component, "") != 0) {
		strcat(pathname, "/");
		strcat(pathname, path_component);
	}
	return pathname;
}

void 
flashcache_ctr_procfs(struct cache_c *dmc)
{
	char *s;
	struct proc_dir_entry *entry;

	s =  flashcache_cons_procfs_cachename(dmc, "");
	entry = proc_mkdir(s, NULL);
	kfree(s);
	if (entry == NULL)
		return;

	s = flashcache_cons_procfs_cachename(dmc, "flashcache_stats");
	#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		entry = create_proc_entry(s, 0, NULL);
		if (entry) {
			entry->proc_fops =  &flashcache_stats_operations;
			entry->data = dmc;
		}
	#endif
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		entry = proc_create_data(s, 0, NULL, &flashcache_stats_operations, dmc);
	#endif
	kfree(s);

	s = flashcache_cons_procfs_cachename(dmc, "flashcache_errors");
	#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		entry = create_proc_entry(s, 0, NULL);
		if (entry) {
			entry->proc_fops =  &flashcache_errors_operations;
			entry->data = dmc;
		}
	#endif
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		entry = proc_create_data(s, 0, NULL, &flashcache_errors_operations, dmc);
	#endif
	kfree(s);

	s = flashcache_cons_procfs_cachename(dmc, "flashcache_iosize_hist");
	#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		entry = create_proc_entry(s, 0, NULL);
		if (entry) {
			entry->proc_fops =  &flashcache_iosize_hist_operations;
			entry->data = dmc;
		}
	#endif
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		entry = proc_create_data(s, 0, NULL, &flashcache_iosize_hist_operations, dmc);
	#endif
	kfree(s);

	s = flashcache_cons_procfs_cachename(dmc, "flashcache_pidlists");
	#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		entry = create_proc_entry(s, 0, NULL);
		if (entry) {
			entry->proc_fops =  &flashcache_pidlists_operations;
			entry->data = dmc;			
		}
	#endif
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		entry = proc_create_data(s, 0, NULL, &flashcache_pidlists_operations, dmc);
	#endif
	kfree(s);

	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK)
		flashcache_writeback_sysctl_register(dmc);
	else
		flashcache_writethrough_sysctl_register(dmc);
}

void 
flashcache_dtr_procfs(struct cache_c *dmc)
{
	char *s;
	
	s = flashcache_cons_procfs_cachename(dmc, "flashcache_stats");
	remove_proc_entry(s, NULL);
	kfree(s);

	s = flashcache_cons_procfs_cachename(dmc, "flashcache_errors");
	remove_proc_entry(s, NULL);
	kfree(s);

	s = flashcache_cons_procfs_cachename(dmc, "flashcache_iosize_hist");
	remove_proc_entry(s, NULL);
	kfree(s);

	s = flashcache_cons_procfs_cachename(dmc, "flashcache_pidlists");
	remove_proc_entry(s, NULL);
	kfree(s);

	s = flashcache_cons_procfs_cachename(dmc, "");
	remove_proc_entry(s, NULL);
	kfree(s);

	if (dmc->cache_mode == FLASHCACHE_WRITE_BACK)
		flashcache_writeback_sysctl_unregister(dmc);
	else
		flashcache_writethrough_sysctl_unregister(dmc);

}

