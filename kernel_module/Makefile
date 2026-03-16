obj-m := traffic_analyzer.o

traffic_analyzer-objs := \
    src/module_main.o \
    src/netfilter_hook.o \
    src/packet_parser.o \
    src/stats.o \
    src/proc_interface.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean