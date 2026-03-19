#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/in.h>
#include <linux/slab.h>
#include "../include/traffic_analyzer.h"
#include "../include/dns_map.h"
#include "../include/route_store.h"

#define PROC_CONNECTIONS "traffic_analyzer"
#define PROC_PROCESSES "traffic_analyzer_procs"
#define PROC_DNS_FLOWS "traffic_analyzer_dns"
#define PROC_ANOMALIES "traffic_analyzer_anomalies"
#define PROC_DNS_MAP "traffic_analyzer_dns_map"
#define PROC_ROUTES "traffic_analyzer_routes"
#define PROC_ROUTES_PENDING "traffic_analyzer_routes_pending"

static const char *proto_to_str(u8 proto)
{
    switch (proto)
    {
    case IPPROTO_TCP:
        return "TCP";
    case IPPROTO_UDP:
        return "UDP";
    default:
        return "OTHER";
    }
}

/*
 * domain_for_entry — look up domain for a traffic entry.
 *
 * make_canonical() swaps src/dst so the lower IP is always stored as
 * src_ip.  For outgoing connections the remote (internet) IP is often
 * numerically lower than the gateway IP, so it ends up in src_ip while
 * dest_ip holds the gateway/router address.
 *
 * We therefore try both IPs and use whichever one resolves first.
 * The result is written directly into e->domain so it is cached for
 * subsequent reads.
 */
static const char *domain_for_entry(struct traffic_entry *e)
{
    if (e->domain[0])
        return e->domain;

    /* Try dest_ip first (common case for truly outgoing flows) */
    dns_map_lookup(e->dest_ip, e->domain, DOMAIN_NAME_MAX);
    if (e->domain[0])
        return e->domain;

    /* Fall back to src_ip (canonical-swap case) */
    dns_map_lookup(e->src_ip, e->domain, DOMAIN_NAME_MAX);
    if (e->domain[0])
        return e->domain;

    return "-";
}

/* ================================================================
 * /proc/traffic_analyzer — connections
 * ================================================================ */
static int conn_show(struct seq_file *m, void *v)
{
    struct traffic_node *node;
    u64 now = ktime_get_real_seconds();

    seq_puts(m,
             "PID|UID|PROCESS|RESOLVED|STATE|DNS|PROTO|"
             "SRC_IP|DEST_IP|SRC_PORT|DEST_PORT|DOMAIN|"
             "OUT_BYTES|IN_BYTES|OUT_PKTS|IN_PKTS|"
             "RATE_OUT_BPS|RATE_IN_BPS|"
             "FIRST_SEEN|LAST_SEEN|DURATION|CLOSED_AT\n");

    spin_lock_bh(&stats_lock);

    list_for_each_entry(node, &traffic_list, list)
    {
        struct traffic_entry *e = &node->entry;
        u64 duration = now - e->first_seen;

        seq_printf(m,
                   "%d|%u|%s|%s|%s|%s|%s|"
                   "%pI4|%pI4|%u|%u|%s|"
                   "%llu|%llu|%llu|%llu|"
                   "%u|%u|"
                   "%llu|%llu|%llu|%llu\n",
                   e->pid, e->uid, e->comm,
                   e->is_resolved ? "YES" : "NO",
                   conn_state_str(e->state),
                   e->is_dns ? "YES" : "NO",
                   proto_to_str(e->protocol),
                   &e->src_ip, &e->dest_ip,
                   e->src_port, e->dest_port,
                   domain_for_entry(e),
                   e->bytes_out, e->bytes_in,
                   e->packets_out, e->packets_in,
                   e->rate.rate_out_bps, e->rate.rate_in_bps,
                   e->first_seen, e->last_seen,
                   duration, e->closed_at);
    }

    spin_unlock_bh(&stats_lock);
    return 0;
}

/* ================================================================
 * /proc/traffic_analyzer_procs — per-process
 * ================================================================ */
static int proc_show(struct seq_file *m, void *v)
{
    struct proc_node *pnode;

    seq_puts(m,
             "PID|UID|PROCESS|EXE|"
             "TCP_CONNS|UDP_CONNS|TOTAL_CONNS|SYN_PENDING|"
             "OUT_BYTES|IN_BYTES|OUT_PKTS|IN_PKTS|"
             "RATE_OUT_BPS|RATE_IN_BPS|"
             "TCP_PCT|UDP_PCT|ANOMALY|"
             "TOP1|TOP2|TOP3|TOP4|TOP5\n");

    spin_lock_bh(&stats_lock);

    list_for_each_entry(pnode, &proc_list, list)
    {
        struct proc_entry *e = &pnode->entry;
        int i;

        seq_printf(m,
                   "%d|%u|%s|%s|"
                   "%u|%u|%u|%u|"
                   "%llu|%llu|%llu|%llu|"
                   "%u|%u|"
                   "%u|%u|%s",
                   e->pid, e->uid, e->comm,
                   e->exe[0] ? e->exe : "unknown",
                   e->tcp_conns, e->udp_conns,
                   e->total_conns, e->syn_pending,
                   e->bytes_out, e->bytes_in,
                   e->packets_out, e->packets_in,
                   e->rate_out_bps, e->rate_in_bps,
                   e->tcp_pct, e->udp_pct,
                   anomaly_str(e->anomaly_flags));

        for (i = 0; i < PROC_TOP_CONNS; i++)
        {
            if (i < e->top_count)
            {
                struct top_conn *tc = &e->top[i];
                if (tc->domain[0])
                    seq_printf(m, "|%s:%u/%s/%llu",
                               tc->domain, tc->remote_port,
                               proto_to_str(tc->protocol),
                               tc->total_bytes);
                else
                    seq_printf(m, "|%pI4:%u/%s/%llu",
                               &tc->remote_ip, tc->remote_port,
                               proto_to_str(tc->protocol),
                               tc->total_bytes);
            }
            else
            {
                seq_puts(m, "|-");
            }
        }
        seq_putc(m, '\n');
    }

    spin_unlock_bh(&stats_lock);
    return 0;
}

/* ================================================================
 * /proc/traffic_analyzer_dns — DNS flows
 * ================================================================ */
static int dns_show(struct seq_file *m, void *v)
{
    struct traffic_node *node;
    u64 now = ktime_get_real_seconds();

    seq_puts(m,
             "PID|UID|PROCESS|SRC_IP|DEST_IP|SRC_PORT|DEST_PORT|"
             "OUT_BYTES|IN_BYTES|OUT_PKTS|IN_PKTS|LAST_SEEN_AGO\n");

    spin_lock_bh(&stats_lock);

    list_for_each_entry(node, &traffic_list, list)
    {
        struct traffic_entry *e = &node->entry;
        if (!e->is_dns)
            continue;
        seq_printf(m,
                   "%d|%u|%s|%pI4|%pI4|%u|%u|%llu|%llu|%llu|%llu|%llu\n",
                   e->pid, e->uid, e->comm,
                   &e->src_ip, &e->dest_ip,
                   e->src_port, e->dest_port,
                   e->bytes_out, e->bytes_in,
                   e->packets_out, e->packets_in,
                   now - e->last_seen);
    }

    spin_unlock_bh(&stats_lock);
    return 0;
}

/* ================================================================
 * /proc/traffic_analyzer_anomalies
 * ================================================================ */
static int anomaly_show(struct seq_file *m, void *v)
{
    struct proc_node *pnode;
    bool any = false;

    seq_puts(m,
             "PID|UID|PROCESS|EXE|ANOMALY|"
             "NEW_CONNS_LAST_SEC|UNIQUE_PORTS_LAST_SEC|"
             "TOTAL_CONNS|SYN_PENDING|RATE_OUT_BPS|RATE_IN_BPS\n");

    spin_lock_bh(&stats_lock);

    list_for_each_entry(pnode, &proc_list, list)
    {
        struct proc_entry *e = &pnode->entry;
        if (e->anomaly_flags == ANOMALY_NONE)
            continue;
        any = true;
        seq_printf(m,
                   "%d|%u|%s|%s|%s|%u|%u|%u|%u|%u|%u\n",
                   e->pid, e->uid, e->comm,
                   e->exe[0] ? e->exe : "unknown",
                   anomaly_str(e->anomaly_flags),
                   e->vel.new_conns_last_sec, e->vel.port_count,
                   e->total_conns, e->syn_pending,
                   e->rate_out_bps, e->rate_in_bps);
    }

    spin_unlock_bh(&stats_lock);

    if (!any)
        seq_puts(m, "# no anomalies detected\n");
    return 0;
}

/* ================================================================
 * /proc/traffic_analyzer_dns_map
 * ================================================================ */
static int dns_map_show(struct seq_file *m, void *v)
{
    seq_puts(m,
             "DOMAIN|IP|TTL_REMAINING|QUERIED_BY_PID|"
             "QUERIED_BY_COMM|FIRST_SEEN|LAST_SEEN\n");

    dns_map_for_each_begin();
    dns_map_seq_show(m);
    dns_map_for_each_end();
    return 0;
}

/* ================================================================
 * /proc/traffic_analyzer_routes
 * ================================================================ */
static int routes_show(struct seq_file *m, void *v)
{
    seq_puts(m,
             "DEST_IP|DOMAIN|STATUS|TOTAL_HOPS|"
             "HOP_N|HOP_IP|HOST|RTT_MS|"
             "CITY|COUNTRY|CC|LAT_E6|LON_E6|ASN|ORG\n");

    route_store_seq_show(m);
    return 0;
}

/* ================================================================
 * /proc/traffic_analyzer_routes_pending
 * ================================================================ */
static int routes_pending_show(struct seq_file *m, void *v)
{
    route_store_pending_seq_show(m);
    return 0;
}

/* ================================================================
 * WRITE HANDLER
 *
 * Handles two classes of writes:
 *   1. Route data from the daemon  (DEST / STATUS / HOP lines)
 *   2. Control commands            (clear, clear_dns, …)
 * ================================================================ */
static ssize_t ta_write(struct file *file,
                        const char __user *buffer,
                        size_t count, loff_t *ppos)
{
    char *buf;
    ssize_t ret = count;

    if (count == 0)
        return 0;

    /* Cap at 64 KB — enough for a full traceroute batch */
    if (count > 65536)
        count = 65536;

    buf = kmalloc(count + 1, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    if (copy_from_user(buf, buffer, count))
    {
        kfree(buf);
        return -EFAULT;
    }
    buf[count] = '\0';

    /* Route data from daemon */
    if (strncmp(buf, "DEST ", 5) == 0 ||
        strncmp(buf, "HOP ", 4) == 0 ||
        strncmp(buf, "STATUS ", 7) == 0)
    {
        route_store_write(buf, count);
        goto out;
    }

    /* Control commands */
    if (strncmp(buf, "clear_routes", 12) == 0)
    {
        route_store_cleanup();
        route_store_init();
    }
    else if (strncmp(buf, "clear_dns_map", 13) == 0)
    {
        dns_map_cleanup();
        dns_map_init();
    }
    else if (strncmp(buf, "clear_dns", 9) == 0)
    {
        struct traffic_node *node, *tmp;
        spin_lock_bh(&stats_lock);
        list_for_each_entry_safe(node, tmp, &traffic_list, list)
        {
            if (node->entry.is_dns)
            {
                list_del(&node->list);
                kfree(node);
            }
        }
        spin_unlock_bh(&stats_lock);
    }
    else if (strncmp(buf, "clear_closed", 12) == 0)
    {
        struct traffic_node *node, *tmp;
        spin_lock_bh(&stats_lock);
        list_for_each_entry_safe(node, tmp, &traffic_list, list)
        {
            if (node->entry.state == CONN_STATE_CLOSED)
            {
                list_del(&node->list);
                kfree(node);
            }
        }
        spin_unlock_bh(&stats_lock);
    }
    else if (strncmp(buf, "clear", 5) == 0)
    {
        stats_cleanup();
    }

out:
    kfree(buf);
    return ret;
}

/* ================================================================
 * OPEN WRAPPERS
 * ================================================================ */
static int conn_open(struct inode *i, struct file *f)
{
    return single_open(f, conn_show, NULL);
}
static int proc_open(struct inode *i, struct file *f)
{
    return single_open(f, proc_show, NULL);
}
static int dns_open(struct inode *i, struct file *f)
{
    return single_open(f, dns_show, NULL);
}
static int anomaly_open(struct inode *i, struct file *f)
{
    return single_open(f, anomaly_show, NULL);
}
static int dns_map_open(struct inode *i, struct file *f)
{
    return single_open(f, dns_map_show, NULL);
}
static int routes_open(struct inode *i, struct file *f)
{
    return single_open(f, routes_show, NULL);
}
static int routes_pending_open(struct inode *i, struct file *f)
{
    return single_open(f, routes_pending_show, NULL);
}

/* ================================================================
 * PROC OPS
 * ================================================================ */
#define MAKE_FOPS(open_fn) {        \
    .proc_open = open_fn,           \
    .proc_read = seq_read,          \
    .proc_write = ta_write,         \
    .proc_lseek = seq_lseek,        \
    .proc_release = single_release, \
}

static const struct proc_ops conn_fops = MAKE_FOPS(conn_open);
static const struct proc_ops proc_fops = MAKE_FOPS(proc_open);
static const struct proc_ops dns_fops = MAKE_FOPS(dns_open);
static const struct proc_ops anomaly_fops = MAKE_FOPS(anomaly_open);
static const struct proc_ops dns_map_fops = MAKE_FOPS(dns_map_open);
static const struct proc_ops routes_fops = MAKE_FOPS(routes_open);
static const struct proc_ops routes_pending_fops = MAKE_FOPS(routes_pending_open);

/* ================================================================
 * INIT / CLEANUP
 * ================================================================ */
int proc_fs_init(void)
{
    if (!proc_create(PROC_CONNECTIONS, 0666, NULL, &conn_fops))
        goto fail_conn;
    if (!proc_create(PROC_PROCESSES, 0666, NULL, &proc_fops))
        goto fail_proc;
    if (!proc_create(PROC_DNS_FLOWS, 0666, NULL, &dns_fops))
        goto fail_dns;
    if (!proc_create(PROC_ANOMALIES, 0666, NULL, &anomaly_fops))
        goto fail_anomaly;
    if (!proc_create(PROC_DNS_MAP, 0666, NULL, &dns_map_fops))
        goto fail_dns_map;
    if (!proc_create(PROC_ROUTES, 0666, NULL, &routes_fops))
        goto fail_routes;
    if (!proc_create(PROC_ROUTES_PENDING, 0444, NULL, &routes_pending_fops))
        goto fail_routes_pending;

    return 0;

fail_routes_pending:
    remove_proc_entry(PROC_ROUTES, NULL);
fail_routes:
    remove_proc_entry(PROC_DNS_MAP, NULL);
fail_dns_map:
    remove_proc_entry(PROC_ANOMALIES, NULL);
fail_anomaly:
    remove_proc_entry(PROC_DNS_FLOWS, NULL);
fail_dns:
    remove_proc_entry(PROC_PROCESSES, NULL);
fail_proc:
    remove_proc_entry(PROC_CONNECTIONS, NULL);
fail_conn:
    printk(KERN_ERR "[TA] failed to create /proc entries\n");
    return -ENOMEM;
}

void proc_fs_cleanup(void)
{
    remove_proc_entry(PROC_ROUTES_PENDING, NULL);
    remove_proc_entry(PROC_ROUTES, NULL);
    remove_proc_entry(PROC_DNS_MAP, NULL);
    remove_proc_entry(PROC_ANOMALIES, NULL);
    remove_proc_entry(PROC_DNS_FLOWS, NULL);
    remove_proc_entry(PROC_PROCESSES, NULL);
    remove_proc_entry(PROC_CONNECTIONS, NULL);
}