/**
 * @file stats.c
 * @brief Core flow and per-process statistics engine.
 * @details The engine stores canonical per-connection counters on a locked
 * traffic list and rebuilds process aggregates once per second. Cleanup also
 * calculates byte rates, applies state TTLs, and derives anomaly bitmasks used
 * by /proc consumers.
 * @author Kernel Traffic Analyzer Project
 * @license GPL-2.0
 */

#include <linux/ip.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timer.h>
#include "../include/kta_api.h"

static LIST_HEAD(traffic_list);
static LIST_HEAD(proc_list);
static DEFINE_SPINLOCK(stats_lock);
static struct timer_list cleanup_timer;
static u64 total_packets;
static u64 total_bytes;
static u32 traffic_entries;
static u32 proc_entries;
static ktime_t module_started;

struct proc_port_scratch {
	pid_t pid;
	__be16 ports[ANOMALY_PORT_SCAN];
	u32 port_count;
};

static struct proc_port_scratch proc_port_scratch[MAX_PROC_ENTRIES];

/**
 * state_to_ttl_secs() - Convert a connection state to a TTL.
 * @state: Connection state.
 * @return: TTL in seconds.
 * @note: Unknown and TIME_WAIT states use conservative short retention.
 */
static unsigned int state_to_ttl_secs(enum kta_conn_state state)
{
	switch (state) {
	case KTA_STATE_SYN_SENT:
		return TTL_SYN_SENT;
	case KTA_STATE_SYN_RECEIVED:
		return TTL_SYN_RECEIVED;
	case KTA_STATE_CLOSED:
	case KTA_STATE_TIME_WAIT:
		return TTL_CLOSED;
	case KTA_STATE_FIN_WAIT:
		return TTL_FIN_WAIT;
	case KTA_STATE_UDP:
		return TTL_UDP;
	case KTA_STATE_ESTABLISHED:
	default:
		return TTL_ESTABLISHED;
	}
}

/**
 * state_to_string() - Convert a connection state to display text.
 * @state: Connection state.
 * @return: Static state name string.
 * @note: Strings are stable for seq_file output.
 */
static const char *state_to_string(enum kta_conn_state state)
{
	switch (state) {
	case KTA_STATE_SYN_SENT:
		return "SYN_SENT";
	case KTA_STATE_SYN_RECEIVED:
		return "SYN_RECEIVED";
	case KTA_STATE_ESTABLISHED:
		return "ESTABLISHED";
	case KTA_STATE_FIN_WAIT:
		return "FIN_WAIT";
	case KTA_STATE_CLOSED:
		return "CLOSED";
	case KTA_STATE_TIME_WAIT:
		return "TIME_WAIT";
	case KTA_STATE_UDP:
		return "UDP";
	default:
		return "UNKNOWN";
	}
}

/**
 * proto_to_string() - Convert an IP protocol to display text.
 * @protocol: IP protocol value.
 * @return: Static protocol name string.
 * @note: Only TCP and UDP are tracked by the parser.
 */
static const char *proto_to_string(u8 protocol)
{
	if (protocol == IPPROTO_TCP)
		return "TCP";
	if (protocol == IPPROTO_UDP)
		return "UDP";
	return "OTHER";
}

/**
 * format_ktime_stats() - Format ktime as UTC ISO-8601 text.
 * @time: ktime value to format.
 * @buf: Destination buffer.
 * @len: Destination buffer length.
 * @return: None.
 * @note: ktime values stored by this module use ktime_get_real().
 */
static void format_ktime_stats(ktime_t time, char *buf, size_t len)
{
	struct timespec64 ts = ktime_to_timespec64(time);
	struct tm tm;

	time64_to_tm(ts.tv_sec, 0, &tm);
	snprintf(buf, len, "%04ld-%02d-%02dT%02d:%02d:%02d.%09ldZ",
		 (long)tm.tm_year + 1900L, tm.tm_mon + 1, tm.tm_mday,
		 tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec);
}

/**
 * flow_equal() - Compare canonical flow keys.
 * @left: First flow key.
 * @right: Second flow key.
 * @return: True when both keys match exactly.
 * @note: Callers store canonical keys with zeroed padding.
 */
static bool flow_equal(const struct flow_key *left, const struct flow_key *right)
{
	return memcmp(left, right, sizeof(*left)) == 0;
}

/**
 * traffic_find_locked() - Find a traffic entry by canonical key.
 * @key: Canonical flow key.
 * @return: Matching entry or NULL.
 * @note: Caller must hold stats_lock.
 */
static struct traffic_entry *traffic_find_locked(const struct flow_key *key)
{
	struct traffic_entry *entry;

	list_for_each_entry(entry, &traffic_list, list) {
		if (flow_equal(&entry->key, key))
			return entry;
	}

	return NULL;
}

/**
 * traffic_evict_locked() - Evict one traffic entry when the table is full.
 * @return: None.
 * @note: Preference is CLOSED, then UDP, then oldest remaining entry.
 */
static void traffic_evict_locked(void)
{
	struct traffic_entry *entry;
	struct traffic_entry *candidate = NULL;

	list_for_each_entry(entry, &traffic_list, list) {
		if (entry->state == KTA_STATE_CLOSED) {
			candidate = entry;
			break;
		}
		if (!candidate || ktime_before(entry->last_seen, candidate->last_seen))
			candidate = entry;
	}
	if (!candidate) {
		list_for_each_entry(entry, &traffic_list, list) {
			if (entry->state == KTA_STATE_UDP) {
				candidate = entry;
				break;
			}
		}
	}
	if (candidate) {
		list_del(&candidate->list);
		kfree(candidate);
		if (traffic_entries)
			traffic_entries--;
	}
}

/**
 * clear_proc_list_locked() - Free all process aggregate rows.
 * @return: None.
 * @note: Caller must hold stats_lock.
 */
static void clear_proc_list_locked(void)
{
	struct proc_entry *entry;
	struct proc_entry *tmp;

	list_for_each_entry_safe(entry, tmp, &proc_list, list) {
		list_del(&entry->list);
		kfree(entry);
	}
	proc_entries = 0;
}

/**
 * proc_whitelisted() - Check whether SYN flood detection should be suppressed.
 * @name: Process name.
 * @return: True for known network diagnostic clients.
 * @note: Whitelist names are exact process-name prefixes.
 */
static bool proc_whitelisted(const char *name)
{
	static const char * const whitelist[] = {
		"nmap", "curl", "wget", "ping", "traceroute",
		"traceroute6", "mtr"
	};
	unsigned int idx;

	for (idx = 0; idx < ARRAY_SIZE(whitelist); idx++) {
		if (strncmp(name, whitelist[idx], strlen(whitelist[idx])) == 0)
			return true;
	}
	return false;
}

/**
 * proc_find_locked() - Find a process aggregate row by PID.
 * @pid: PID to find.
 * @return: Matching process entry or NULL.
 * @note: Caller must hold stats_lock.
 */
static struct proc_entry *proc_find_locked(pid_t pid)
{
	struct proc_entry *entry;

	list_for_each_entry(entry, &proc_list, list) {
		if (entry->pid == pid)
			return entry;
	}

	return NULL;
}

/**
 * proc_count_unique_port() - Track a destination port in a fixed scratch list.
 * @ports: Scratch port array.
 * @count: In/out number of unique ports.
 * @port: Destination port in network byte order.
 * @return: None.
 * @note: The caller only needs exactness up to ANOMALY_PORT_SCAN.
 */
static void proc_count_unique_port(__be16 *ports, u32 *count, __be16 port)
{
	u32 idx;

	for (idx = 0; idx < *count; idx++) {
		if (ports[idx] == port)
			return;
	}
	if (*count < ANOMALY_PORT_SCAN)
		ports[(*count)++] = port;
}

/**
 * rebuild_proc_list_locked() - Rebuild process aggregates from traffic rows.
 * @return: None.
 * @note: Uses GFP_ATOMIC because the recurring cleanup runs from timer context.
 */
static void rebuild_proc_list_locked(void)
{
	struct traffic_entry *traffic;
	ktime_t now = ktime_get_real();
	u32 scratch_count = 0;

	clear_proc_list_locked();
	memset(proc_port_scratch, 0, sizeof(proc_port_scratch));

	list_for_each_entry(traffic, &traffic_list, list) {
		struct proc_entry *proc;
		u32 idx;

		if (traffic->pid <= 0)
			continue;
		proc = proc_find_locked(traffic->pid);
		if (!proc) {
			if (proc_entries >= MAX_PROC_ENTRIES)
				continue;
			proc = kzalloc(sizeof(*proc), GFP_ATOMIC);
			if (!proc) {
				pr_err("kta: stats: proc allocation failed\n");
				continue;
			}
			INIT_LIST_HEAD(&proc->list);
			proc->pid = traffic->pid;
			proc->uid = traffic->uid;
			strlcpy(proc->proc_name, traffic->proc_name,
				sizeof(proc->proc_name));
			proc->first_seen = traffic->first_seen;
			list_add_tail(&proc->list, &proc_list);
			proc_entries++;
		}

		proc->conn_count++;
		if (traffic->key.protocol == IPPROTO_TCP)
			proc->tcp_count++;
		else if (traffic->key.protocol == IPPROTO_UDP)
			proc->udp_count++;
		proc->total_bytes_in += traffic->bytes_in;
		proc->total_bytes_out += traffic->bytes_out;
		proc->rate_in += traffic->rate_in;
		proc->rate_out += traffic->rate_out;
		if (traffic->state == KTA_STATE_SYN_SENT ||
		    traffic->state == KTA_STATE_SYN_RECEIVED)
			proc->pending_syn_count++;
		if (ktime_ms_delta(now, traffic->first_seen) <=
		    RATE_WINDOW_SECS * MSEC_PER_SEC)
			proc->new_conns_per_sec++;
		if (ktime_before(traffic->first_seen, proc->first_seen))
			proc->first_seen = traffic->first_seen;

		for (idx = 0; idx < scratch_count; idx++) {
			if (proc_port_scratch[idx].pid == traffic->pid)
				break;
		}
		if (idx == scratch_count && scratch_count < MAX_PROC_ENTRIES) {
			proc_port_scratch[idx].pid = traffic->pid;
			proc_port_scratch[idx].port_count = 0;
			scratch_count++;
		}
		if (idx < scratch_count) {
			proc_count_unique_port(proc_port_scratch[idx].ports,
					       &proc_port_scratch[idx].port_count,
					       traffic->key.dst_port);
			proc->unique_dst_ports =
				proc_port_scratch[idx].port_count;
		}
	}

	list_for_each_entry(traffic, &traffic_list, list)
		traffic->anomaly_flags = 0;

	{
		struct proc_entry *proc;

		list_for_each_entry(proc, &proc_list, list) {
			if (proc->new_conns_per_sec >= ANOMALY_CONN_BURST)
				proc->anomaly_flags |= ANOMALY_FLAG_CONN_BURST;
			if (proc->unique_dst_ports >= ANOMALY_PORT_SCAN)
				proc->anomaly_flags |= ANOMALY_FLAG_PORT_SCAN;
			if (proc->conn_count >= ANOMALY_HIGH_CONNS)
				proc->anomaly_flags |= ANOMALY_FLAG_HIGH_CONNS;
			if (proc->conn_count &&
			    ((proc->pending_syn_count * 100U) / proc->conn_count) >=
				    ANOMALY_SYN_FLOOD_PCT &&
			    !proc_whitelisted(proc->proc_name))
				proc->anomaly_flags |= ANOMALY_FLAG_SYN_FLOOD;
			if (proc->rate_in + proc->rate_out >= ANOMALY_HIGH_BW_BYTES)
				proc->anomaly_flags |= ANOMALY_FLAG_HIGH_BW;

			list_for_each_entry(traffic, &traffic_list, list) {
				if (traffic->pid == proc->pid)
					traffic->anomaly_flags = proc->anomaly_flags;
			}
		}
	}
}

/**
 * stats_cleanup_timer() - Recurring cleanup and aggregation timer.
 * @timer: Timer instance.
 * @return: None.
 * @note: Runs once per CLEANUP_INTERVAL_SECS and reschedules itself.
 */
static void stats_cleanup_timer(struct timer_list *timer)
{
	struct traffic_entry *entry;
	struct traffic_entry *tmp;

	spin_lock_bh(&stats_lock);
	list_for_each_entry_safe(entry, tmp, &traffic_list, list) {
		if (time_after(jiffies, entry->ttl_jiffies)) {
			list_del(&entry->list);
			kfree(entry);
			if (traffic_entries)
				traffic_entries--;
			continue;
		}
		entry->rate_in = entry->bytes_in - entry->bytes_in_prev;
		entry->rate_out = entry->bytes_out - entry->bytes_out_prev;
		entry->bytes_in_prev = entry->bytes_in;
		entry->bytes_out_prev = entry->bytes_out;
		if (entry->rate_in + entry->rate_out >= ANOMALY_HIGH_BW_BYTES)
			entry->anomaly_flags |= ANOMALY_FLAG_HIGH_BW;
	}
	rebuild_proc_list_locked();
	spin_unlock_bh(&stats_lock);

	mod_timer(&cleanup_timer, jiffies + CLEANUP_INTERVAL_SECS * HZ);
}

/**
 * stats_init() - Initialize statistics state and start cleanup timer.
 * @return: Zero on success.
 * @note: Must run before Netfilter hooks are registered.
 */
int stats_init(void)
{
	INIT_LIST_HEAD(&traffic_list);
	INIT_LIST_HEAD(&proc_list);
	total_packets = 0;
	total_bytes = 0;
	traffic_entries = 0;
	proc_entries = 0;
	module_started = ktime_get_real();
	timer_setup(&cleanup_timer, stats_cleanup_timer, 0);
	mod_timer(&cleanup_timer, jiffies + CLEANUP_INTERVAL_SECS * HZ);
	return 0;
}

/**
 * stats_exit() - Stop cleanup and free all statistics entries.
 * @return: None.
 * @note: Called after packet hooks and /proc interfaces are removed.
 */
void stats_exit(void)
{
	struct traffic_entry *entry;
	struct traffic_entry *tmp;

	del_timer_sync(&cleanup_timer);
	spin_lock_bh(&stats_lock);
	list_for_each_entry_safe(entry, tmp, &traffic_list, list) {
		list_del(&entry->list);
		kfree(entry);
	}
	traffic_entries = 0;
	clear_proc_list_locked();
	spin_unlock_bh(&stats_lock);
}

/**
 * stats_update() - Update counters for one parsed packet.
 * @key: Canonical flow key.
 * @pid: Resolved PID or zero.
 * @uid: Packet owner UID.
 * @proc_name: Process name or "unknown".
 * @pkt_len: Packet length in bytes.
 * @is_inbound: True for LOCAL_IN packets, false for LOCAL_OUT.
 * @state: Parsed connection state.
 * @return: None.
 * @note: Uses GFP_ATOMIC because it is called from Netfilter hooks.
 */
void stats_update(const struct flow_key *key, pid_t pid, uid_t uid,
		  const char *proc_name, u32 pkt_len, bool is_inbound,
		  enum kta_conn_state state)
{
	struct traffic_entry *entry;
	struct flow_key canonical;
	ktime_t now;

	if (!key)
		return;

	canonical = *key;
	make_canonical(&canonical);
	now = ktime_get_real();

	spin_lock_bh(&stats_lock);
	entry = traffic_find_locked(&canonical);
	if (!entry) {
		if (traffic_entries >= MAX_TRAFFIC_ENTRIES)
			traffic_evict_locked();
		entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
		if (!entry) {
			spin_unlock_bh(&stats_lock);
			pr_err("kta: stats: traffic allocation failed\n");
			return;
		}
		INIT_LIST_HEAD(&entry->list);
		entry->key = canonical;
		entry->pid = pid;
		entry->uid = uid;
		strlcpy(entry->proc_name,
			proc_name && proc_name[0] ? proc_name : "unknown",
			sizeof(entry->proc_name));
		strlcpy(entry->exe_path, "unknown", sizeof(entry->exe_path));
		entry->state = state;
		entry->first_seen = now;
		entry->last_seen = now;
		entry->ttl_jiffies = jiffies + state_to_ttl_secs(state) * HZ;
		entry->pid_resolved = pid > 0;
		list_add_tail(&entry->list, &traffic_list);
		traffic_entries++;
	} else if (!entry->pid_resolved && pid > 0) {
		entry->pid = pid;
		entry->uid = uid;
		entry->pid_resolved = true;
		strlcpy(entry->proc_name,
			proc_name && proc_name[0] ? proc_name : "unknown",
			sizeof(entry->proc_name));
	}

	entry->last_seen = now;
	entry->state = state;
	entry->ttl_jiffies = jiffies + state_to_ttl_secs(state) * HZ;
	if (is_inbound) {
		entry->bytes_in += pkt_len;
		entry->packets_in++;
	} else {
		entry->bytes_out += pkt_len;
		entry->packets_out++;
	}
	if (dns_map_lookup(entry->key.dst_ip, entry->domain,
			   sizeof(entry->domain)) ||
	    dns_map_lookup(entry->key.src_ip, entry->domain,
			   sizeof(entry->domain)))
		entry->dns_resolved = true;

	total_packets++;
	total_bytes += pkt_len;
	spin_unlock_bh(&stats_lock);
}

/**
 * stats_get_total_packets() - Return total packets observed.
 * @return: Total packet counter.
 * @note: Sampled under stats_lock.
 */
u64 stats_get_total_packets(void)
{
	u64 value;

	spin_lock_bh(&stats_lock);
	value = total_packets;
	spin_unlock_bh(&stats_lock);

	return value;
}

/**
 * stats_get_total_bytes() - Return total bytes observed.
 * @return: Total byte counter.
 * @note: Sampled under stats_lock.
 */
u64 stats_get_total_bytes(void)
{
	u64 value;

	spin_lock_bh(&stats_lock);
	value = total_bytes;
	spin_unlock_bh(&stats_lock);

	return value;
}

/**
 * stats_seq_show_connections() - Emit per-connection rows.
 * @m: seq_file receiving output.
 * @return: None.
 * @note: Used by /proc/traffic_analyzer.
 */
void stats_seq_show_connections(struct seq_file *m)
{
	struct traffic_entry *entry;
	char first[PROC_TIME_BUF_LEN];
	char last[PROC_TIME_BUF_LEN];

	spin_lock_bh(&stats_lock);
	list_for_each_entry(entry, &traffic_list, list) {
		format_ktime_stats(entry->first_seen, first, sizeof(first));
		format_ktime_stats(entry->last_seen, last, sizeof(last));
		seq_printf(m,
			   "%d|%u|%s|%s|%s|%s|%s|%s|%pI4|%u|%pI4|%u|%s|%llu|%llu|%llu|%llu|%llu|%llu|%s|%s|0x%02x\n",
			   entry->pid, entry->uid, entry->proc_name,
			   entry->exe_path,
			   entry->pid_resolved ? "yes" : "no",
			   state_to_string(entry->state),
			   entry->dns_resolved ? "yes" : "no",
			   proto_to_string(entry->key.protocol),
			   &entry->key.src_ip, ntohs(entry->key.src_port),
			   &entry->key.dst_ip, ntohs(entry->key.dst_port),
			   entry->domain[0] ? entry->domain : "-",
			   entry->bytes_in, entry->bytes_out,
			   entry->packets_in, entry->packets_out,
			   entry->rate_in, entry->rate_out, first, last,
			   entry->anomaly_flags);
	}
	spin_unlock_bh(&stats_lock);
}

/**
 * stats_seq_show_processes() - Emit per-process aggregate rows.
 * @m: seq_file receiving output.
 * @return: None.
 * @note: Process rows are rebuilt by the cleanup timer.
 */
void stats_seq_show_processes(struct seq_file *m)
{
	struct proc_entry *entry;

	spin_lock_bh(&stats_lock);
	list_for_each_entry(entry, &proc_list, list) {
		seq_printf(m, "%d|%u|%s|%u|%u|%u|%llu|%llu|%llu|%llu|0x%02x|%u|%u\n",
			   entry->pid, entry->uid, entry->proc_name,
			   entry->conn_count, entry->tcp_count, entry->udp_count,
			   entry->total_bytes_in, entry->total_bytes_out,
			   entry->rate_in, entry->rate_out, entry->anomaly_flags,
			   entry->new_conns_per_sec, entry->unique_dst_ports);
	}
	spin_unlock_bh(&stats_lock);
}

/**
 * anomaly_names() - Convert anomaly flags to display text.
 * @flags: Anomaly bitmask.
 * @buf: Destination buffer.
 * @len: Destination buffer length.
 * @return: None.
 * @note: Names are comma-separated and stable for backend parsing.
 */
static void anomaly_names(u8 flags, char *buf, size_t len)
{
	buf[0] = '\0';
	if (flags & ANOMALY_FLAG_CONN_BURST)
		strlcat(buf, "CONN_BURST,", len);
	if (flags & ANOMALY_FLAG_PORT_SCAN)
		strlcat(buf, "PORT_SCAN,", len);
	if (flags & ANOMALY_FLAG_HIGH_CONNS)
		strlcat(buf, "HIGH_CONNS,", len);
	if (flags & ANOMALY_FLAG_SYN_FLOOD)
		strlcat(buf, "SYN_FLOOD,", len);
	if (flags & ANOMALY_FLAG_HIGH_BW)
		strlcat(buf, "HIGH_BW,", len);
	if (buf[0] && strlen(buf) > 0)
		buf[strlen(buf) - 1] = '\0';
}

/**
 * anomaly_severity() - Classify an anomaly bitmask severity.
 * @flags: Anomaly bitmask.
 * @return: Static severity string.
 * @note: SYN flood and high bandwidth are treated as high severity.
 */
static const char *anomaly_severity(u8 flags)
{
	if (flags & (ANOMALY_FLAG_SYN_FLOOD | ANOMALY_FLAG_HIGH_BW))
		return "high";
	if (flags & (ANOMALY_FLAG_PORT_SCAN | ANOMALY_FLAG_HIGH_CONNS))
		return "medium";
	return "low";
}

/**
 * stats_seq_show_anomalies() - Emit anomalous process rows.
 * @m: seq_file receiving output.
 * @return: None.
 * @note: Only processes with non-zero anomaly_flags are printed.
 */
void stats_seq_show_anomalies(struct seq_file *m)
{
	struct proc_entry *entry;
	char names[PROC_FLAG_BUF_LEN];
	char first[PROC_TIME_BUF_LEN];

	spin_lock_bh(&stats_lock);
	list_for_each_entry(entry, &proc_list, list) {
		if (!entry->anomaly_flags)
			continue;
		anomaly_names(entry->anomaly_flags, names, sizeof(names));
		format_ktime_stats(entry->first_seen, first, sizeof(first));
		seq_printf(m, "%d|%s|0x%02x|%s|%s|%s\n", entry->pid,
			   entry->proc_name, entry->anomaly_flags, names,
			   anomaly_severity(entry->anomaly_flags), first);
	}
	spin_unlock_bh(&stats_lock);
}

/**
 * stats_get_active_connections() - Return active connection row count.
 * @return: Number of traffic entries.
 * @note: Sampled under stats_lock.
 */
u32 stats_get_active_connections(void)
{
	u32 value;

	spin_lock_bh(&stats_lock);
	value = traffic_entries;
	spin_unlock_bh(&stats_lock);

	return value;
}

/**
 * stats_get_active_processes() - Return active process row count.
 * @return: Number of process aggregate rows.
 * @note: Sampled under stats_lock.
 */
u32 stats_get_active_processes(void)
{
	u32 value;

	spin_lock_bh(&stats_lock);
	value = proc_entries;
	spin_unlock_bh(&stats_lock);

	return value;
}

/**
 * stats_get_uptime_sec() - Return module statistics uptime.
 * @return: Seconds since stats_init().
 * @note: Uses real time to match displayed timestamps.
 */
u64 stats_get_uptime_sec(void)
{
	return div_s64(ktime_ms_delta(ktime_get_real(), module_started),
		       MSEC_PER_SEC);
}
