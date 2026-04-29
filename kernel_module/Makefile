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
	@build_m="$(CURDIR)"; copy_back=0; case "$$build_m" in *" "*) \
		build_m="/tmp/kta_kernel_module_build_$$(id -u)"; copy_back=1; \
		rm -rf "$$build_m"; mkdir -p "$$build_m"; cp -R "$(CURDIR)/include" "$(CURDIR)/src" "$(CURDIR)/Makefile" "$$build_m/";; \
	esac; \
	$(MAKE) -C $(KDIR) M="$$build_m" modules; rc=$$?; \
	if [ $$copy_back -eq 1 ] && [ $$rc -eq 0 ]; then cp "$$build_m"/*.ko "$(CURDIR)/"; fi; \
	exit $$rc

clean:
	@build_m="$(CURDIR)"; case "$$build_m" in *" "*) build_m="/tmp/kta_kernel_module_build_$$(id -u)";; esac; \
	if [ -d "$$build_m" ]; then $(MAKE) -C $(KDIR) M="$$build_m" clean; fi
