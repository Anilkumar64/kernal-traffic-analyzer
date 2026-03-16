#include <linux/module.h>
#include <linux/kernel.h>
#include "../include/traffic_analyzer.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anil Reddy");
MODULE_DESCRIPTION("Kernel Traffic Analyzer");
MODULE_VERSION("1.0");

/* Module Init */
static int __init traffic_analyzer_init(void)
{
    printk(KERN_INFO "[traffic_analyzer] module loaded\n");

    proc_init();
    netfilter_hook_init();

    return 0;
}

/* Module Exit */
static void __exit traffic_analyzer_exit(void)
{
    netfilter_hook_exit();
    proc_cleanup();
    stats_cleanup(); /* free traffic entries */

    printk(KERN_INFO "[traffic_analyzer] module unloaded\n");
}

module_init(traffic_analyzer_init);
module_exit(traffic_analyzer_exit);