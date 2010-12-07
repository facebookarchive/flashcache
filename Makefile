all:
	$(MAKE) -C src KERNEL_TREE=$(KERNEL_TREE) PWD=$(PWD)/src

install:
	$(MAKE) -C src KERNEL_TREE=$(KERNEL_TREE) PWD=$(PWD)/src install

clean:
	$(MAKE) -C src KERNEL_TREE=$(KERNEL_TREE) PWD=$(PWD)/src clean
