
COMMIT_REV := $(shell git describe  --always --abbrev=12)
KERNEL_TREE ?= /lib/modules/$(shell uname -r)/build
export COMMIT_REV

all:
	$(MAKE) -C src KERNEL_TREE=$(KERNEL_TREE) PWD=$(shell pwd)/src all

install:
	$(MAKE) -C src KERNEL_TREE=$(KERNEL_TREE) PWD=$(shell pwd)/src install

clean:
	$(MAKE) -C src KERNEL_TREE=$(KERNEL_TREE) PWD=$(shell pwd)/src clean
