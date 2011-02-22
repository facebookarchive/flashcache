EXTRA_CFLAGS=-I$(KERNEL_TREE)/include/ -I$(KERNEL_TREE)/include/linux -I$(KERNEL_TREE)/drivers/md -I./ -DCOMMIT_REV="\"$(COMMIT_REV)\""
UTILS_CFLAGS=-I./ -DCOMMIT_REV="\"$(COMMIT_REV)\""

KERNEL_TREE ?= /lib/modules/$(shell uname -r)/build

obj-m += flashcache.o
flashcache-objs := flashcache_conf.o flashcache_main.o flashcache_subr.o flashcache_ioctl.o

KERNEL_SOURCE_VERSION ?= $(shell uname -r)

all:
	make -C $(KERNEL_TREE) M=$(PWD) modules V=0
	@echo "building utils"
	@$(CC) $(UTILS_CFLAGS) -o utils/flashcache_create utils/flashcache_create.c
	@$(CC) $(UTILS_CFLAGS) -o utils/flashcache_destroy utils/flashcache_destroy.c
	@$(CC) $(UTILS_CFLAGS) -o utils/flashcache_load utils/flashcache_load.c

install: all
	install -o root -g root -m 0755 -d /lib/modules/$(KERNEL_SOURCE_VERSION)/extra/flashcache/
	install -o root -g root -m 0755 flashcache.ko /lib/modules/$(KERNEL_SOURCE_VERSION)/extra/flashcache/
	depmod -a
	install -o root -g root -m 0755 utils/flashcache_create /sbin/
	install -o root -g root -m 0755 utils/flashcache_destroy /sbin/
	install -o root -g root -m 0755 utils/flashcache_load /sbin/

clean:
	make -C $(KERNEL_TREE) M=$(PWD) clean
	rm -f utils/flashcache_{create,destroy,load}
