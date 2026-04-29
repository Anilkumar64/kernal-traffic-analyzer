obj-m += traffic_analyzer.o
traffic_analyzer-objs := src/module_main.o src/netfilter_hook.o \
  src/packet_parser.o src/stats.o src/proc_interface.o src/resolver.o \
  src/sock_cache.o src/inode_cache.o src/flow_cache.o src/exe_resolver.o \
  src/dns_parser.o src/dns_map.o src/route_store.o

ccflags-y := -I$(src)/include -Wall -Wextra

KDIR ?= /lib/modules/$(shell uname -r)/build
KTA_BUILD_DIR ?= /tmp/kta_kernel_module_build
space := $(empty) $(empty)

ifneq ($(findstring $(space),$(CURDIR)),)
all:
	rm -rf $(KTA_BUILD_DIR)
	mkdir -p $(KTA_BUILD_DIR)
	cp -a include src Makefile $(KTA_BUILD_DIR)/
	$(MAKE) -C $(KDIR) M=$(KTA_BUILD_DIR) modules
	cp $(KTA_BUILD_DIR)/traffic_analyzer.ko .
clean:
	rm -rf $(KTA_BUILD_DIR) .*.cmd *.ko *.mod *.mod.c *.o Module.symvers modules.order src/*.o src/.*.cmd
else
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
endif
