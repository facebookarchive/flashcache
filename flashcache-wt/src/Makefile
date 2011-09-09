EXTRA_CFLAGS=-I$(KERNEL_TREE)/drivers/md -I./
EXTRA_CFLAGS += -I$(KERNEL_TREE)/include/ -I$(KERNEL_TREE)/include/linux
UTILS_CFLAGS=-I./

obj-m += flashcache-wt.o
flashcache-wt-objs := flashcache_wt.o

KERNEL_SOURCE_VERSION ?= $(shell uname -r)

all:
	make -C $(KERNEL_TREE) M=$(PWD) modules
	$(CC) $(UTILS_CFLAGS) -o utils/flashcache_wt_create utils/flashcache_wt_create.c

install: all
	install -o root -g root -m 0755 -d /lib/modules/$(KERNEL_SOURCE_VERSION)/extra/flashcache/
	install -o root -g root -m 0755 flashcache-wt.ko /lib/modules/$(KERNEL_SOURCE_VERSION)/extra/flashcache/
	depmod -a
	install -o root -g root -m 0755 utils/flashcache_wt_create /sbin/

clean:
	make -C $(KERNEL_TREE) M=$(PWD) clean
	rm -f utils/flashcache_wt_create
