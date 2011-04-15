COMMIT_REV ?= $(shell git describe  --always --abbrev=12)
CFLAGS += 
PROGRAMS += flashcache 
INSTALL_DIR = /usr/lib/ocf/resource.d/flashcache

.PHONY:all
all: $(PROGRAMS)

.PHONY: install
install: $(PROGRAMS)
	install -d -m 755 $(INSTALL_DIR)
	install -m 755 $(PROGRAMS) $(INSTALL_DIR)

.PHONY: clean
clean:
