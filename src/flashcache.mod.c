#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
};

static const struct modversion_info ____versions[]
__attribute_used__
__attribute__((section("__versions"))) = {
	{ 0x1a131742, "struct_module" },
	{ 0x3642ec5a, "proc_dointvec_minmax" },
	{ 0xa78896f5, "kmem_cache_destroy" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0xf9a482f9, "msleep" },
	{ 0xd6ee688f, "vmalloc" },
	{ 0xdbb705ec, "register_sysctl_table" },
	{ 0x6a2fe464, "single_open" },
	{ 0xa0fbac79, "wake_up_bit" },
	{ 0x4c0da1da, "dm_get_device" },
	{ 0xc8b57c27, "autoremove_wake_function" },
	{ 0x83917ba, "single_release" },
	{ 0xc35147e6, "malloc_sizes" },
	{ 0xdc99e36, "proc_dointvec" },
	{ 0x970c4dcf, "find_task_by_pid_type" },
	{ 0xf8c00c66, "dm_table_get_mode" },
	{ 0xa28e76e6, "schedule_work" },
	{ 0x8f8db519, "seq_printf" },
	{ 0xbab1fdd7, "remove_proc_entry" },
	{ 0x7b04cc91, "mempool_destroy" },
	{ 0x2fd1d81c, "vfree" },
	{ 0x9292a13d, "dm_register_target" },
	{ 0xeaa456ed, "_spin_lock_irqsave" },
	{ 0xdfdc96b3, "seq_read" },
	{ 0x7d11c268, "jiffies" },
	{ 0x6f06534f, "blk_get_backing_dev_info" },
	{ 0xfcaa04a0, "out_of_line_wait_on_bit_lock" },
	{ 0xa13798f8, "printk_ratelimit" },
	{ 0x183fa88b, "mempool_alloc_slab" },
	{ 0xd7ea771e, "del_timer_sync" },
	{ 0xdd132261, "printk" },
	{ 0x859204af, "sscanf" },
	{ 0x57f46cef, "_spin_lock_irq" },
	{ 0x1075bf0, "panic" },
	{ 0x91e2c84a, "dm_unregister_target" },
	{ 0x7ec9bfbc, "strncpy" },
	{ 0xed5aeabf, "sysctl_intvec" },
	{ 0x6057a993, "mem_section" },
	{ 0x970e9589, "dm_io_async_bvec" },
	{ 0x27147e64, "_spin_unlock_irqrestore" },
	{ 0xfeae9a7, "dm_io_put" },
	{ 0x8a99a016, "mempool_free_slab" },
	{ 0xb3576650, "dm_io_get" },
	{ 0x9ca95a0e, "sort" },
	{ 0xcd405baa, "bio_endio" },
	{ 0x3980aac1, "unregister_reboot_notifier" },
	{ 0x761cee10, "kmem_cache_alloc" },
	{ 0x1740c28, "__free_pages" },
	{ 0xb2780f36, "mempool_alloc" },
	{ 0x1cc6719a, "register_reboot_notifier" },
	{ 0xadba4622, "unregister_sysctl_table" },
	{ 0x93fca811, "__get_free_pages" },
	{ 0xaae5b8e9, "schedule_delayed_work" },
	{ 0x1000e51, "schedule" },
	{ 0x8659f63b, "mempool_create" },
	{ 0x6b2dc060, "dump_stack" },
	{ 0xf3fba395, "create_proc_entry" },
	{ 0x6f2d5c7, "mempool_free" },
	{ 0xf45c547b, "kcopyd_client_create" },
	{ 0xdd41d0ba, "kmem_cache_create" },
	{ 0xffd3c7, "init_waitqueue_head" },
	{ 0x438c2350, "init_timer" },
	{ 0x994e1983, "__wake_up" },
	{ 0x6acbe2ff, "kmem_cache_zalloc" },
	{ 0x72270e35, "do_gettimeofday" },
	{ 0x56193b3a, "seq_lseek" },
	{ 0x37a0cba, "kfree" },
	{ 0x801678, "flush_scheduled_work" },
	{ 0x2caa52dc, "prepare_to_wait" },
	{ 0x1e7f6773, "dm_io_async_vm" },
	{ 0x7bb4de17, "scnprintf" },
	{ 0x9ee29a75, "blkdev_driver_ioctl" },
	{ 0x5878e0d0, "finish_wait" },
	{ 0x5135a67c, "dm_put_device" },
	{ 0xebd3ae8d, "kcopyd_copy" },
	{ 0x3302b500, "copy_from_user" },
	{ 0x582405c5, "kcopyd_client_destroy" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=dm-mod";


MODULE_INFO(srcversion, "3A3ACABA2CCA5DF3F2D004C");
