EXTRA_CFLAGS=-I$(KERNEL_TREE)/drivers/md -I./
UTILS_CFLAGS=-I./

obj-m += flashcache-wt.o
flashcache-wt-objs := flashcache_wt.o

all:
	make -C $(KERNEL_TREE) M=$(PWD) modules
	$(CC) $(UTILS_CFLAGS) -o utils/flashcache_wt_create utils/flashcache_wt_create.c

clean:
	make -C $(KERNEL_TREE) M=$(PWD) clean
	rm -f utils/flashcache_wt_create
