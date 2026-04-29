obj-m += traffic_analyzer.o

traffic_analyzer-objs := \
    src/module_main.o      \
    src/netfilter_hook.o   \
    src/packet_parser.o    \
    src/resolver.o         \
    src/stats.o            \
    src/proc_interface.o   \
    src/cache.o            \
    src/inode_cache.o      \
    src/sock_cache.o       \
    src/flow_cache.o       \
    src/exe_resolver.o     \
    src/dns_map.o          \
    src/dns_parser.o       \
    src/route_store.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
