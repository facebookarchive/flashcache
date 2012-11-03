COMMIT_REV ?= $(shell git describe  --always --abbrev=12)
KERNEL_SOURCE_VERSION ?= $(shell uname -r)
KERNEL_TREE ?= /lib/modules/$(KERNEL_SOURCE_VERSION)/build
export COMMIT_REV

# Check for RHEL/CentOS
RHEL5_VER ?= $(shell if [ -e /etc/redhat-release ]; then grep 5.[0-9] /etc/redhat-release; else false; fi)
ifneq "$(RHEL5_VER)" ""
	RHEL5_TREE := /usr/src/redhat/BUILD/kernel-2.6.18/linux-$(shell uname -r).$(shell uname -i)
	KERNEL_TREE := $(RHEL5_TREE)
endif

all:
	$(MAKE) -C src KERNEL_TREE=$(KERNEL_TREE) PWD=$(shell pwd)/src all

install:
	$(MAKE) -C src KERNEL_TREE=$(KERNEL_TREE) PWD=$(shell pwd)/src install

clean:
	$(MAKE) -C src KERNEL_TREE=$(KERNEL_TREE) PWD=$(shell pwd)/src clean
