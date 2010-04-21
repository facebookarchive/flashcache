all:
	$(MAKE) -C src KERNEL_TREE=$(KERNEL_TREE) PWD=$(PWD)/src

clean:
	$(MAKE) -C src KERNEL_TREE=$(KERNEL_TREE) PWD=$(PWD)/src clean
