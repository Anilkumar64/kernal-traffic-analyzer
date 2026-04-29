#include <linux/module.h>
#include <linux/kernel.h>
#include "../include/traffic_analyzer.h"
#include "../include/cache.h"
#include "../include/inode_cache.h"
#include "../include/sock_cache.h"
#include "../include/flow_cache.h"
#include "../include/resolver.h"
#include "../include/exe_resolver.h"
#include "../include/dns_map.h"
#include "../include/route_store.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anil Reddy");
MODULE_DESCRIPTION("Kernel Traffic Analyzer");
MODULE_VERSION("1.0");

/* KTA v1.0 */

static int __init traffic_analyzer_init(void)
{
    int ret;

    printk(KERN_INFO "[traffic_analyzer] Initializing module v1.0\n");

    ret = proc_fs_init();
    if (ret)
        return ret;

    cache_init();
    inode_cache_init();
    sock_cache_init();
    flow_cache_init();
    exe_cache_init();
    dns_map_init();
    route_store_init();
    resolver_init();

    ret = net_hook_init();
    if (ret)
    {
        printk(KERN_ERR "[TA] net_hook_init failed: %d\n", ret);
        resolver_cleanup();
        route_store_cleanup();
        dns_map_cleanup();
        exe_cache_cleanup();
        flow_cache_cleanup();
        sock_cache_cleanup();
        inode_cache_cleanup();
        cache_cleanup();
        proc_fs_cleanup();
        return ret;
    }

    printk(KERN_INFO "[traffic_analyzer] Module loaded\n");
    return 0;
}

static void __exit traffic_analyzer_exit(void)
{
    printk(KERN_INFO "[traffic_analyzer] Cleaning up\n");

    net_hook_cleanup();
    resolver_cleanup();
    stats_cleanup();
    route_store_cleanup();
    dns_map_cleanup();
    exe_cache_cleanup();
    flow_cache_cleanup();
    sock_cache_cleanup();
    inode_cache_cleanup();
    cache_cleanup();
    proc_fs_cleanup();

    printk(KERN_INFO "[traffic_analyzer] Module unloaded\n");
}

module_init(traffic_analyzer_init);
module_exit(traffic_analyzer_exit);
