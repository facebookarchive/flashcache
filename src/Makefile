COMMIT_REV ?= $(shell git describe  --always --abbrev=12)
KERNEL_SOURCE_VERSION ?= $(shell uname -r)
KERNEL_TREE ?= /lib/modules/$(KERNEL_SOURCE_VERSION)/build

EXTRA_CFLAGS += -I$(KERNEL_TREE)/drivers/md -I./ -DCOMMIT_REV="\"$(COMMIT_REV)\""
EXTRA_CFLAGS += -I$(KERNEL_TREE)/include/ -I$(KERNEL_TREE)/include/linux 

# Check for RHEL/CentOS
RHEL5_VER ?= $(shell  if [ -e /etc/redhat-release ]; then grep 5.[0-9] /etc/redhat-release; else false; fi)
RHEL5_SETUP :=
ifneq "$(RHEL5_VER)" ""
	RHEL5_SETUP := rhel5-setup
	RHEL5_SPEC := /usr/src/redhat/SPECS/kernel.spec
	RHEL5_TREE := /usr/src/redhat/BUILD/kernel-2.6.18/linux-$(shell uname -r).$(shell uname -i)
	RHEL5_SRC := /usr/src/kernels/$(shell uname -r)-$(shell uname -i)
	KERNEL_TREE := $(RHEL5_TREE)
endif

obj-m += flashcache.o
flashcache-objs := flashcache_conf.o flashcache_main.o flashcache_subr.o flashcache_ioctl.o flashcache_procfs.o

.PHONY: all
all: modules utils

.PHONY:    modules
modules: $(RHEL5_SETUP)
	make -C $(KERNEL_TREE) M=$(PWD) modules V=0

.PHONY:    utils
utils:
	make -C utils all

.PHONY: modules_install
modules_install: modules
	install -o root -g root -m 0755 -d $(DESTDIR)/lib/modules/$(KERNEL_SOURCE_VERSION)/extra/flashcache/
	install -o root -g root -m 0644 flashcache.ko $(DESTDIR)/lib/modules/$(KERNEL_SOURCE_VERSION)/extra/flashcache/

.PHONY: utils_install
utils_install: utils
	make -C utils install

.PHONY: ocf_install
ocf_install:
	make -C ocf install

.PHONY: depmod
depmod:
	depmod -a

.PHONY: install
install: modules_install utils_install ocf_install depmod

.PHONY: clean
clean:
	make -C $(KERNEL_TREE) M=$(PWD) clean
	make -C utils clean

.PHONY: rhel5-setup
rhel5-setup: $(RHEL5_TREE)
	make -C $(RHEL5_TREE) oldconfig ; \
	make -C $(RHEL5_TREE) prepare modules_prepare
	ln -s -f $(RHEL5_SRC)/Module.symvers $(RHEL5_TREE)/Module.symvers

$(RHEL5_TREE):
	rpmbuild -bp --target=`uname -m` $(RHEL5_SPEC) 2>&1 | tee `dirname $(RHEL5_SPEC)`/prep.log
