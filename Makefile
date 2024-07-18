obj-m := dodol.o
CC = gcc -wall
KDIR := /lib/modules$(shell uname -r)/build
PWD := $(shell pwd)

all: 
	$(MAKE) -c $(KDIR) M=$(PWD) modules

clean: 
	$(MAKE) -c $(KDIR) M=$(PWD) clean