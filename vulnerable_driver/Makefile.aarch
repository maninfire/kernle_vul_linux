#CC = aarch64-linux-gnu-
#PWD:=$(shell pwd)

KDIR = /home/lier/work/linux-4.4.58/build
EXTRA_CFLAGS += -fno-stack-protector
EXTRA_CFLAGS += -g
EXTRA_CFLAGS += -o0

obj-m += src/vuln_driver.o
#CFLAGS_vuln_driver.o = -o0
all:

	make -C $(KDIR) M=$(PWD)  modules ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-
clean:
	rm -rf src/*.ko
	rm -rf src/*.mod
	rm -rf src/*.mod.*
	rm -rf src/*.o
	rm Module.symvers
	rm modules.order
