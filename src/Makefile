COMMIT_REV ?= $(shell git describe  --always --abbrev=12)
KERNEL_SOURCE_VERSION ?= $(shell uname -r)
KERNEL_TREE ?= /lib/modules/$(KERNEL_SOURCE_VERSION)/build

EXTRA_CFLAGS += -I$(KERNEL_TREE)/drivers/md -I./ -DCOMMIT_REV="\"$(COMMIT_REV)\""
EXTRA_CFLAGS += -I$(KERNEL_TREE)/include/ -I$(KERNEL_TREE)/include/linux 

obj-m += flashcache.o
flashcache-objs := flashcache_conf.o flashcache_main.o flashcache_subr.o flashcache_ioctl.o flashcache_procfs.o

.PHONY: all
all: modules utils

.PHONY:    modules
modules:
	make -C $(KERNEL_TREE) M=$(PWD) modules V=0

.PHONY:    utils
utils:
	make -C utils all

.PHONY: modules_install
modules_install: modules
	install -o root -g root -m 0755 -d /lib/modules/$(KERNEL_SOURCE_VERSION)/extra/flashcache/
	install -o root -g root -m 0755 flashcache.ko /lib/modules/$(KERNEL_SOURCE_VERSION)/extra/flashcache/
	depmod -a

.PHONY: utils_install
utils_install: utils
	make -C utils install

.PHONY: install
install: modules_install utils_install

.PHONY: clean

clean:
	make -C $(KERNEL_TREE) M=$(PWD) clean
	make -C utils clean
