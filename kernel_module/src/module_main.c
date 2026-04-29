/**
 * @file module_main.c
 * @brief Kernel Traffic Analyzer module lifecycle.
 * @details Module initialization brings subsystems up in dependency order and
 * tears down partial initialization in reverse order on failure. Exit performs
 * the exact reverse sequence so hooks stop before shared state disappears.
 * @author Kernel Traffic Analyzer Project
 * @license GPL-2.0
 */

#include <linux/init.h>
#include <linux/module.h>
#include "../include/kta_api.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernel Traffic Analyzer Project");
MODULE_DESCRIPTION("Per-process network traffic analyzer via Netfilter");
MODULE_VERSION("1.0.0");

/**
 * traffic_analyzer_init() - Initialize the Kernel Traffic Analyzer module.
 * @return: Zero on success or a negative errno from the failing subsystem.
 * @note: Subsystems are initialized in the order required by the public API.
 */
static int __init traffic_analyzer_init(void)
{
	int ret;

	ret = dns_map_init();
	if (ret)
		goto fail;
	pr_info("kta: dns_map initialized\n");

	ret = sock_cache_init();
	if (ret)
		goto fail_sock;
	pr_info("kta: sock_cache initialized\n");

	ret = inode_cache_init();
	if (ret)
		goto fail_inode;
	pr_info("kta: inode_cache initialized\n");

	ret = flow_cache_init();
	if (ret)
		goto fail_flow;
	pr_info("kta: flow_cache initialized\n");

	ret = exe_cache_init();
	if (ret)
		goto fail_exe;
	pr_info("kta: exe_cache initialized\n");

	ret = resolver_init();
	if (ret)
		goto fail_resolver;
	pr_info("kta: resolver initialized\n");

	ret = route_store_init();
	if (ret)
		goto fail_route;
	pr_info("kta: route_store initialized\n");

	ret = stats_init();
	if (ret)
		goto fail_stats;
	pr_info("kta: stats initialized\n");

	ret = proc_init();
	if (ret)
		goto fail_proc;
	pr_info("kta: proc_interface initialized\n");

	ret = nf_hook_init();
	if (ret)
		goto fail_nf;
	pr_info("kta: netfilter_hook initialized\n");

	pr_info("kta: module initialized\n");
	return 0;

fail_nf:
	proc_exit();
	pr_info("kta: proc_interface destroyed\n");
fail_proc:
	stats_exit();
	pr_info("kta: stats destroyed\n");
fail_stats:
	route_store_exit();
	pr_info("kta: route_store destroyed\n");
fail_route:
	resolver_exit();
	pr_info("kta: resolver destroyed\n");
fail_resolver:
	exe_cache_exit();
	pr_info("kta: exe_cache destroyed\n");
fail_exe:
	flow_cache_exit();
	pr_info("kta: flow_cache destroyed\n");
fail_flow:
	inode_cache_exit();
	pr_info("kta: inode_cache destroyed\n");
fail_inode:
	sock_cache_exit();
	pr_info("kta: sock_cache destroyed\n");
fail_sock:
	dns_map_exit();
	pr_info("kta: dns_map destroyed\n");
fail:
	pr_err("kta: module_main: initialization failed: %d\n", ret);
	return ret ? ret : -EFAULT;
}

/**
 * traffic_analyzer_exit() - Tear down the Kernel Traffic Analyzer module.
 * @return: None.
 * @note: Teardown order is the exact reverse of successful initialization.
 */
static void __exit traffic_analyzer_exit(void)
{
	nf_hook_exit();
	pr_info("kta: netfilter_hook destroyed\n");
	proc_exit();
	pr_info("kta: proc_interface destroyed\n");
	stats_exit();
	pr_info("kta: stats destroyed\n");
	route_store_exit();
	pr_info("kta: route_store destroyed\n");
	resolver_exit();
	pr_info("kta: resolver destroyed\n");
	exe_cache_exit();
	pr_info("kta: exe_cache destroyed\n");
	flow_cache_exit();
	pr_info("kta: flow_cache destroyed\n");
	inode_cache_exit();
	pr_info("kta: inode_cache destroyed\n");
	sock_cache_exit();
	pr_info("kta: sock_cache destroyed\n");
	dns_map_exit();
	pr_info("kta: dns_map destroyed\n");
	pr_info("kta: module destroyed\n");
}

module_init(traffic_analyzer_init);
module_exit(traffic_analyzer_exit);

