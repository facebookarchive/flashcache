EXTRA_CFLAGS=-I$(KERNEL_TREE)/drivers/md -I./
UTILS_CFLAGS=-I./

obj-m += flashcache.o
flashcache-objs := flashcache_conf.o flashcache_main.o flashcache_subr.o

all:
	make -C $(KERNEL_TREE) M=$(PWD) modules
	$(CC) $(UTILS_CFLAGS) -o utils/flashcache_create utils/flashcache_create.c
	$(CC) $(UTILS_CFLAGS) -o utils/flashcache_destroy utils/flashcache_destroy.c
	$(CC) $(UTILS_CFLAGS) -o utils/flashcache_load utils/flashcache_load.c

clean:
	make -C $(KERNEL_TREE) M=$(PWD) clean
	rm -f utils/flashcache_{create,destroy,load}
