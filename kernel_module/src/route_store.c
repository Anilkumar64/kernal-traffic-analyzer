/**
 * @file route_store.c
 * @brief Traceroute pending and completed route store.
 * @details The kernel module only requests route enrichment and stores daemon
 * results. Pending target IPs are deduplicated in one list, completed hop rows
 * are stored in another, and writes accept a strict pipe-delimited daemon
 * format with bounded string fields.
 * @author Kernel Traffic Analyzer Project
 * @license GPL-2.0
 */

#include <linux/inet.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include "../include/kta_api.h"

static LIST_HEAD(pending_list);
static LIST_HEAD(route_list);
static DEFINE_SPINLOCK(route_store_lock);
static u32 route_done_entries;
static u32 route_pending_entries;

/**
 * route_store_init() - Initialize route store lists.
 * @return: Zero on success.
 * @note: Lists are statically allocated.
 */
int route_store_init(void)
{
	INIT_LIST_HEAD(&pending_list);
	INIT_LIST_HEAD(&route_list);
	route_done_entries = 0;
	route_pending_entries = 0;
	return 0;
}

/**
 * route_store_free_list() - Free all entries in a route list.
 * @head: List head to drain.
 * @count: Counter to reset after draining.
 * @return: None.
 * @note: Caller must hold route_store_lock.
 */
static void route_store_free_list(struct list_head *head, u32 *count)
{
	struct route_entry *entry;
	struct route_entry *tmp;

	list_for_each_entry_safe(entry, tmp, head, list) {
		list_del(&entry->list);
		kfree(entry);
	}
	*count = 0;
}

/**
 * route_store_exit() - Free all pending and completed route entries.
 * @return: None.
 * @note: Called after /proc files are removed.
 */
void route_store_exit(void)
{
	spin_lock_bh(&route_store_lock);
	route_store_free_list(&pending_list, &route_pending_entries);
	route_store_free_list(&route_list, &route_done_entries);
	spin_unlock_bh(&route_store_lock);
}

/**
 * route_find_locked() - Find an IP in a route list.
 * @head: List head to scan.
 * @ip: Target IP in network byte order.
 * @return: Matching entry or NULL.
 * @note: Caller must hold route_store_lock.
 */
static struct route_entry *route_find_locked(struct list_head *head, __be32 ip)
{
	struct route_entry *entry;

	list_for_each_entry(entry, head, list) {
		if (entry->target_ip == ip)
			return entry;
	}

	return NULL;
}

/**
 * route_store_request() - Add a pending route request for an IP.
 * @ip: Target IP in network byte order.
 * @return: None.
 * @note: Duplicate pending or completed targets are ignored.
 */
void route_store_request(__be32 ip)
{
	struct route_entry *entry;

	if (!ip)
		return;

	spin_lock_bh(&route_store_lock);
	if (route_find_locked(&pending_list, ip) ||
	    route_find_locked(&route_list, ip)) {
		spin_unlock_bh(&route_store_lock);
		return;
	}
	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		spin_unlock_bh(&route_store_lock);
		pr_err("kta: route_store: allocation failed\n");
		return;
	}
	entry->target_ip = ip;
	entry->pending = true;
	list_add_tail(&entry->list, &pending_list);
	route_pending_entries++;
	spin_unlock_bh(&route_store_lock);
}

/**
 * route_store_is_pending() - Check whether an IP awaits daemon processing.
 * @ip: Target IP in network byte order.
 * @return: True when @ip is pending.
 * @note: Used by /proc stats and route deduplication.
 */
bool route_store_is_pending(__be32 ip)
{
	bool pending;

	spin_lock_bh(&route_store_lock);
	pending = route_find_locked(&pending_list, ip) != NULL;
	spin_unlock_bh(&route_store_lock);

	return pending;
}

/**
 * route_store_is_done() - Check whether an IP has completed route data.
 * @ip: Target IP in network byte order.
 * @return: True when at least one completed hop exists.
 * @note: Multiple hop rows may share the same target IP.
 */
bool route_store_is_done(__be32 ip)
{
	bool done;

	spin_lock_bh(&route_store_lock);
	done = route_find_locked(&route_list, ip) != NULL;
	spin_unlock_bh(&route_store_lock);

	return done;
}

/**
 * route_parse_ip() - Parse a dotted IPv4 field.
 * @field: NUL-terminated field string.
 * @ip: Destination network-order IPv4 address.
 * @return: Zero on success, negative errno on failure.
 * @note: Uses in4_pton for strict bounded parsing.
 */
static int route_parse_ip(const char *field, __be32 *ip)
{
	if (!field || !ip ||
	    !in4_pton(field, -1, (u8 *)ip, -1, NULL))
		return -EINVAL;
	return 0;
}

/**
 * route_split_fields() - Split a route result line into fields.
 * @buf: Mutable line buffer.
 * @fields: Destination field pointer array.
 * @return: Zero when all required fields are present.
 * @note: Exactly ROUTE_RESULT_FIELDS fields are required.
 */
static int route_split_fields(char *buf, char *fields[ROUTE_RESULT_FIELDS])
{
	unsigned int idx;
	char *cursor = buf;

	for (idx = 0; idx < ROUTE_RESULT_FIELDS; idx++) {
		fields[idx] = strsep(&cursor, "|");
		if (!fields[idx] || !fields[idx][0])
			return -EINVAL;
	}
	if (cursor && cursor[0])
		return -EINVAL;

	return 0;
}

/**
 * route_store_write_result() - Store one daemon-produced route hop row.
 * @line: Pipe-delimited daemon line.
 * @len: Number of bytes supplied by the daemon.
 * @return: Bytes consumed on success or negative errno.
 * @note: Expected format is IP|HOP_NUM|HOP_IP|RTT_MS|COUNTRY|LAT|LON|ASN|ORG.
 */
int route_store_write_result(const char *line, size_t len)
{
	char *buf;
	char *fields[ROUTE_RESULT_FIELDS];
	struct route_entry *pending;
	struct route_entry *entry;
	__be32 target_ip;
	__be32 hop_ip;
	unsigned int hop_num;
	unsigned int rtt_ms;
	int ret;

	if (!line || !len || len >= ROUTE_RESULT_MAX_LEN)
		return -EINVAL;

	buf = kzalloc(len + 1, GFP_KERNEL);
	if (!buf) {
		pr_err("kta: route_store: write buffer allocation failed\n");
		return -ENOMEM;
	}
	memcpy(buf, line, len);
	strim(buf);

	ret = route_split_fields(buf, fields);
	if (ret)
		goto out;
	ret = route_parse_ip(fields[0], &target_ip);
	if (ret)
		goto out;
	ret = route_parse_ip(fields[2], &hop_ip);
	if (ret)
		goto out;
	ret = kstrtouint(fields[1], 10, &hop_num);
	if (ret || hop_num > U8_MAX) {
		ret = -EINVAL;
		goto out;
	}
	ret = kstrtouint(fields[3], 10, &rtt_ms);
	if (ret)
		goto out;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		pr_err("kta: route_store: result allocation failed\n");
		ret = -ENOMEM;
		goto out;
	}
	entry->target_ip = target_ip;
	entry->pending = false;
	entry->hop_num = (u8)hop_num;
	entry->hop_ip = hop_ip;
	entry->rtt_ms = rtt_ms;
	strlcpy(entry->country, fields[4], sizeof(entry->country));
	strlcpy(entry->lat, fields[5], sizeof(entry->lat));
	strlcpy(entry->lon, fields[6], sizeof(entry->lon));
	strlcpy(entry->asn, fields[7], sizeof(entry->asn));
	strlcpy(entry->org, fields[8], sizeof(entry->org));

	spin_lock_bh(&route_store_lock);
	pending = route_find_locked(&pending_list, target_ip);
	if (pending) {
		list_del(&pending->list);
		kfree(pending);
		if (route_pending_entries)
			route_pending_entries--;
	}
	list_add_tail(&entry->list, &route_list);
	route_done_entries++;
	spin_unlock_bh(&route_store_lock);
	ret = (int)len;

out:
	kfree(buf);
	return ret;
}

/**
 * route_store_seq_show_routes() - Emit completed route rows.
 * @m: seq_file receiving output.
 * @return: None.
 * @note: Caller is the /proc route reader.
 */
void route_store_seq_show_routes(struct seq_file *m)
{
	struct route_entry *entry;

	spin_lock_bh(&route_store_lock);
	list_for_each_entry(entry, &route_list, list) {
		seq_printf(m, "%pI4|%u|%pI4|%u|%s|%s|%s|%s|%s\n",
			   &entry->target_ip, entry->hop_num, &entry->hop_ip,
			   entry->rtt_ms, entry->country, entry->lat,
			   entry->lon, entry->asn, entry->org);
	}
	spin_unlock_bh(&route_store_lock);
}

/**
 * route_store_seq_show_pending() - Emit pending route target IPs.
 * @m: seq_file receiving output.
 * @return: None.
 * @note: One target IP is emitted per line.
 */
void route_store_seq_show_pending(struct seq_file *m)
{
	struct route_entry *entry;

	spin_lock_bh(&route_store_lock);
	list_for_each_entry(entry, &pending_list, list)
		seq_printf(m, "%pI4\n", &entry->target_ip);
	spin_unlock_bh(&route_store_lock);
}

/**
 * route_store_done_count() - Return completed route row count.
 * @return: Number of completed hop rows.
 * @note: Sampled under route_store_lock.
 */
u32 route_store_done_count(void)
{
	u32 count;

	spin_lock_bh(&route_store_lock);
	count = route_done_entries;
	spin_unlock_bh(&route_store_lock);

	return count;
}

