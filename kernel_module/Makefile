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
BUILD_M := $(if $(findstring $(space),$(CURDIR)),/tmp/kta_kernel_module_$(shell id -u),$(CURDIR))

space := $(empty) $(empty)

all:
	@if [ "$(BUILD_M)" != "$(CURDIR)" ]; then ln -sfn "$(CURDIR)" "$(BUILD_M)"; fi
	$(MAKE) -C $(KDIR) M="$(BUILD_M)" modules

clean:
	@if [ "$(BUILD_M)" != "$(CURDIR)" ]; then ln -sfn "$(CURDIR)" "$(BUILD_M)"; fi
	$(MAKE) -C $(KDIR) M="$(BUILD_M)" clean
