COMMIT_REV ?= $(shell git describe  --always --abbrev=12)
CFLAGS += -I.. -I. -DCOMMIT_REV="\"$(COMMIT_REV)\""
PROGRAMS += flashcache_create flashcache_destroy flashcache_load
INSTALL_DIR = /sbin/

.PHONY:all
all: $(PROGRAMS)

flashcache_create: flashcache_create.o
	$(CC) $^ -o $@

-include flashcache_create.d

flashcache_destroy: flashcache_destroy.o
	$(CC) $^ -o $@

-include flashcache_destroy.d

flashcache_load: flashcache_load.o
	$(CC) $^ -o $@

-include flashcache_load.d

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) -MF $*.d -MT $*.o $*.c

.PHONY: install
install: $(PROGRAMS)
	install -d -m 755 $(INSTALL_DIR)
	install -m 755 $(PROGRAMS) $(INSTALL_DIR)

.PHONY: clean
clean:
	rm -f *.[od] $(PROGRAMS)

