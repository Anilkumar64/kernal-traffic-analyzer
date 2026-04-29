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
	@build_m="$(CURDIR)"; case "$$build_m" in *" "*) build_m="/tmp/kta_kernel_module_$$(id -u)"; ln -sfn "$(CURDIR)" "$$build_m";; esac; \
	$(MAKE) -C $(KDIR) M="$$build_m" modules

clean:
	@build_m="$(CURDIR)"; case "$$build_m" in *" "*) build_m="/tmp/kta_kernel_module_$$(id -u)"; ln -sfn "$(CURDIR)" "$$build_m";; esac; \
	$(MAKE) -C $(KDIR) M="$$build_m" clean
