/**
 * @file proc_interface.c
 * @brief /proc interface for Kernel Traffic Analyzer data.
 * @details This file creates the stable text ABI consumed by later backend and
 * GUI tasks. Read paths use seq_file helpers, while the completed route file
 * also exposes a bounded write handler for daemon-produced traceroute results.
 * @author Kernel Traffic Analyzer Project
 * @license GPL-2.0
 */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "../include/kta_api.h"

#define PROC_TRAFFIC "traffic_analyzer"
#define PROC_PROCS "traffic_analyzer_procs"
#define PROC_DNS "traffic_analyzer_dns"
#define PROC_ANOMALY "traffic_analyzer_anomaly"
#define PROC_ROUTES "traffic_analyzer_routes"
#define PROC_ROUTES_PENDING "traffic_analyzer_routes_pending"
#define PROC_STATS "traffic_analyzer_stats"

static struct proc_dir_entry *proc_entries[7];

/**
 * proc_single_start() - Start a one-shot seq_file iteration.
 * @m: seq_file instance.
 * @pos: Current read position.
 * @return: SEQ_START_TOKEN for the first position, otherwise NULL.
 * @note: Used by proc_create_seq read-only files.
 */
static void *proc_single_start(struct seq_file *m, loff_t *pos)
{
	return *pos == 0 ? SEQ_START_TOKEN : NULL;
}

/**
 * proc_single_next() - Advance a one-shot seq_file iteration.
 * @m: seq_file instance.
 * @v: Current iterator token.
 * @pos: Current read position.
 * @return: Always NULL after the first row set.
 * @note: Header and body are emitted from each show callback.
 */
static void *proc_single_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	return NULL;
}

/**
 * proc_single_stop() - Stop a one-shot seq_file iteration.
 * @m: seq_file instance.
 * @v: Iterator token.
 * @return: None.
 * @note: No iterator storage is allocated.
 */
static void proc_single_stop(struct seq_file *m, void *v)
{
}

/**
 * traffic_show() - Emit /proc/traffic_analyzer.
 * @m: seq_file receiving output.
 * @v: Iterator token.
 * @return: Zero.
 * @note: Header order is the backend contract.
 */
static int traffic_show(struct seq_file *m, void *v)
{
	seq_puts(m,
		 "PID|UID|PROCESS|EXE|RESOLVED|STATE|DNS|PROTO|SRC_IP|SRC_PORT|DST_IP|DST_PORT|DOMAIN|BYTES_IN|BYTES_OUT|PKTS_IN|PKTS_OUT|RATE_IN|RATE_OUT|FIRST_SEEN|LAST_SEEN|ANOMALY_FLAGS\n");
	stats_seq_show_connections(m);
	return 0;
}

/**
 * procs_show() - Emit /proc/traffic_analyzer_procs.
 * @m: seq_file receiving output.
 * @v: Iterator token.
 * @return: Zero.
 * @note: Rows are produced from the latest rebuilt process snapshot.
 */
static int procs_show(struct seq_file *m, void *v)
{
	seq_puts(m,
		 "PID|UID|PROCESS|CONNECTIONS|TCP_COUNT|UDP_COUNT|TOTAL_IN|TOTAL_OUT|RATE_IN|RATE_OUT|ANOMALY_FLAGS|NEW_CONNS_SEC|UNIQUE_DST_PORTS\n");
	stats_seq_show_processes(m);
	return 0;
}

/**
 * dns_show() - Emit /proc/traffic_analyzer_dns.
 * @m: seq_file receiving output.
 * @v: Iterator token.
 * @return: Zero.
 * @note: DNS rows are current cache entries.
 */
static int dns_show(struct seq_file *m, void *v)
{
	seq_puts(m, "IP|DOMAIN|FIRST_SEEN|LAST_SEEN|QUERY_COUNT\n");
	dns_map_seq_show(m);
	return 0;
}

/**
 * anomaly_show() - Emit /proc/traffic_analyzer_anomaly.
 * @m: seq_file receiving output.
 * @v: Iterator token.
 * @return: Zero.
 * @note: Only processes with non-zero anomaly flags are emitted.
 */
static int anomaly_show(struct seq_file *m, void *v)
{
	seq_puts(m, "PID|PROCESS|ANOMALY_FLAGS|FLAG_NAMES|SEVERITY|FIRST_SEEN\n");
	stats_seq_show_anomalies(m);
	return 0;
}

/**
 * routes_show() - Emit /proc/traffic_analyzer_routes.
 * @m: seq_file receiving output.
 * @v: Iterator token.
 * @return: Zero.
 * @note: This file is also writable through routes_write().
 */
static int routes_show(struct seq_file *m, void *v)
{
	seq_puts(m, "TARGET_IP|HOP_NUM|HOP_IP|RTT_MS|COUNTRY|LAT|LON|ASN|ORG\n");
	route_store_seq_show_routes(m);
	return 0;
}

/**
 * routes_pending_show() - Emit /proc/traffic_analyzer_routes_pending.
 * @m: seq_file receiving output.
 * @v: Iterator token.
 * @return: Zero.
 * @note: One pending IP is emitted per row.
 */
static int routes_pending_show(struct seq_file *m, void *v)
{
	seq_puts(m, "IP\n");
	route_store_seq_show_pending(m);
	return 0;
}

/**
 * stats_show() - Emit /proc/traffic_analyzer_stats.
 * @m: seq_file receiving output.
 * @v: Iterator token.
 * @return: Zero.
 * @note: Values are simple key/value rows separated by pipes.
 */
static int stats_show(struct seq_file *m, void *v)
{
	seq_printf(m, "TOTAL_PACKETS|%llu\n", stats_get_total_packets());
	seq_printf(m, "TOTAL_BYTES|%llu\n", stats_get_total_bytes());
	seq_printf(m, "ACTIVE_CONNECTIONS|%u\n", stats_get_active_connections());
	seq_printf(m, "ACTIVE_PROCESSES|%u\n", stats_get_active_processes());
	seq_printf(m, "DNS_ENTRIES|%u\n", dns_map_count());
	seq_printf(m, "MODULE_UPTIME_SEC|%llu\n", stats_get_uptime_sec());
	return 0;
}

static const struct seq_operations traffic_seq_ops = {
	.start = proc_single_start,
	.next = proc_single_next,
	.stop = proc_single_stop,
	.show = traffic_show,
};
static const struct seq_operations procs_seq_ops = {
	.start = proc_single_start,
	.next = proc_single_next,
	.stop = proc_single_stop,
	.show = procs_show,
};
static const struct seq_operations dns_seq_ops = {
	.start = proc_single_start,
	.next = proc_single_next,
	.stop = proc_single_stop,
	.show = dns_show,
};
static const struct seq_operations anomaly_seq_ops = {
	.start = proc_single_start,
	.next = proc_single_next,
	.stop = proc_single_stop,
	.show = anomaly_show,
};
static const struct seq_operations routes_pending_seq_ops = {
	.start = proc_single_start,
	.next = proc_single_next,
	.stop = proc_single_stop,
	.show = routes_pending_show,
};
static const struct seq_operations stats_seq_ops = {
	.start = proc_single_start,
	.next = proc_single_next,
	.stop = proc_single_stop,
	.show = stats_show,
};

/**
 * routes_open() - Open the writable routes proc file.
 * @inode: Proc inode.
 * @file: Opened file.
 * @return: Zero on success or negative errno.
 * @note: single_open is used so the write handler can coexist with seq output.
 */
static int routes_open(struct inode *inode, struct file *file)
{
	return single_open(file, routes_show, NULL);
}

/**
 * routes_write() - Accept one route result line from the daemon.
 * @file: Proc file.
 * @ubuf: User buffer.
 * @count: User byte count.
 * @ppos: File offset pointer.
 * @return: Count consumed on success or negative errno.
 * @note: Input is copied into a bounded kernel buffer before validation.
 */
static ssize_t routes_write(struct file *file, const char __user *ubuf,
			    size_t count, loff_t *ppos)
{
	char *buf;
	int ret;

	if (!ubuf || !count || count >= ROUTE_RESULT_MAX_LEN)
		return -EINVAL;
	buf = kzalloc(count + 1, GFP_KERNEL);
	if (!buf) {
		pr_err("kta: proc_interface: route write allocation failed\n");
		return -ENOMEM;
	}
	if (copy_from_user(buf, ubuf, count)) {
		kfree(buf);
		return -EFAULT;
	}
	ret = route_store_write_result(buf, count);
	kfree(buf);
	if (ret < 0)
		return ret;
	*ppos += ret;
	return ret;
}

static const struct proc_ops routes_proc_ops = {
	.proc_open = routes_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
	.proc_write = routes_write,
};

/**
 * proc_remove_all() - Remove all proc entries created by this module.
 * @return: None.
 * @note: Safe to call after partial initialization.
 */
static void proc_remove_all(void)
{
	unsigned int idx;

	for (idx = 0; idx < ARRAY_SIZE(proc_entries); idx++) {
		if (proc_entries[idx]) {
			proc_remove(proc_entries[idx]);
			proc_entries[idx] = NULL;
		}
	}
}

/**
 * proc_init() - Create all Kernel Traffic Analyzer proc files.
 * @return: Zero on success or negative errno.
 * @note: Routes uses proc_create for write support; read-only files use
 * proc_create_seq and seq_operations.
 */
int proc_init(void)
{
	proc_entries[0] = proc_create_seq(PROC_TRAFFIC, 0444, NULL,
					  &traffic_seq_ops);
	proc_entries[1] = proc_create_seq(PROC_PROCS, 0444, NULL,
					  &procs_seq_ops);
	proc_entries[2] = proc_create_seq(PROC_DNS, 0444, NULL, &dns_seq_ops);
	proc_entries[3] = proc_create_seq(PROC_ANOMALY, 0444, NULL,
					  &anomaly_seq_ops);
	proc_entries[4] = proc_create(PROC_ROUTES, 0644, NULL,
				      &routes_proc_ops);
	proc_entries[5] = proc_create_seq(PROC_ROUTES_PENDING, 0444, NULL,
					  &routes_pending_seq_ops);
	proc_entries[6] = proc_create_seq(PROC_STATS, 0444, NULL,
					  &stats_seq_ops);

	if (!proc_entries[0] || !proc_entries[1] || !proc_entries[2] ||
	    !proc_entries[3] || !proc_entries[4] || !proc_entries[5] ||
	    !proc_entries[6]) {
		pr_err("kta: proc_interface: proc_create failed\n");
		proc_remove_all();
		return -ENOMEM;
	}

	return 0;
}

/**
 * proc_exit() - Remove all proc files.
 * @return: None.
 * @note: Called before backing subsystem state is destroyed.
 */
void proc_exit(void)
{
	proc_remove_all();
}

