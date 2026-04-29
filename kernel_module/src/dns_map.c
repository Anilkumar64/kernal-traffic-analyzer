/**
 * @file dns_map.c
 * @brief LRU DNS IP-to-domain mapping cache.
 * @details DNS responses are parsed in Netfilter context, so this cache uses a
 * fixed-size hash table, spinlock protection, and GFP_ATOMIC allocations. When
 * the table is full the oldest last_seen entry is evicted to preserve recent
 * name attribution for traffic statistics.
 * @author Kernel Traffic Analyzer Project
 * @license GPL-2.0
 */

#include <linux/hashtable.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include "../include/kta_api.h"

static DEFINE_HASHTABLE(dns_hash, DNS_HASH_BITS);
static DEFINE_SPINLOCK(dns_map_lock);
static u32 dns_entries;

/**
 * dns_map_init() - Initialize the DNS cache.
 * @return: Zero on success.
 * @note: Hash table storage is static; initialization only resets counters.
 */
int dns_map_init(void)
{
	hash_init(dns_hash);
	dns_entries = 0;
	return 0;
}

/**
 * dns_map_exit() - Destroy all DNS cache entries.
 * @return: None.
 * @note: Caller must ensure packet hooks are already unregistered.
 */
void dns_map_exit(void)
{
	struct dns_entry *entry;
	struct hlist_node *tmp;
	unsigned int bucket;

	spin_lock_bh(&dns_map_lock);
	hash_for_each_safe(dns_hash, bucket, tmp, entry, hnode) {
		hash_del(&entry->hnode);
		kfree(entry);
	}
	dns_entries = 0;
	spin_unlock_bh(&dns_map_lock);
}

/**
 * dns_map_find_locked() - Find a DNS entry while holding the cache lock.
 * @ip: IPv4 address key in network byte order.
 * @return: Matching entry or NULL.
 * @note: Caller must hold dns_map_lock.
 */
static struct dns_entry *dns_map_find_locked(__be32 ip)
{
	struct dns_entry *entry;

	hash_for_each_possible(dns_hash, entry, hnode, (__force u32)ip) {
		if (entry->ip == ip)
			return entry;
	}

	return NULL;
}

/**
 * dns_map_evict_oldest_locked() - Evict the least recently used DNS entry.
 * @return: None.
 * @note: Caller must hold dns_map_lock.
 */
static void dns_map_evict_oldest_locked(void)
{
	struct dns_entry *entry;
	struct dns_entry *oldest = NULL;
	unsigned int bucket;

	hash_for_each(dns_hash, bucket, entry, hnode) {
		if (!oldest || ktime_before(entry->last_seen, oldest->last_seen))
			oldest = entry;
	}

	if (oldest) {
		hash_del(&oldest->hnode);
		kfree(oldest);
		if (dns_entries)
			dns_entries--;
	}
}

/**
 * dns_map_store() - Insert or update an IP-to-domain DNS mapping.
 * @ip: IPv4 address key in network byte order.
 * @domain: Domain name to associate with @ip.
 * @return: None.
 * @note: Uses GFP_ATOMIC because DNS responses are parsed from hook context.
 */
void dns_map_store(__be32 ip, const char *domain)
{
	struct dns_entry *entry;
	ktime_t now;

	if (!domain || !domain[0])
		return;

	now = ktime_get_real();
	spin_lock_bh(&dns_map_lock);
	entry = dns_map_find_locked(ip);
	if (entry) {
		strlcpy(entry->domain, domain, sizeof(entry->domain));
		entry->last_seen = now;
		entry->query_count++;
		spin_unlock_bh(&dns_map_lock);
		return;
	}

	if (dns_entries >= MAX_DNS_ENTRIES)
		dns_map_evict_oldest_locked();

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		spin_unlock_bh(&dns_map_lock);
		pr_err("kta: dns_map: allocation failed\n");
		return;
	}

	entry->ip = ip;
	strlcpy(entry->domain, domain, sizeof(entry->domain));
	entry->first_seen = now;
	entry->last_seen = now;
	entry->query_count = 1;
	hash_add(dns_hash, &entry->hnode, (__force u32)ip);
	dns_entries++;
	spin_unlock_bh(&dns_map_lock);
}

/**
 * dns_map_lookup() - Look up a DNS mapping by IP address.
 * @ip: IPv4 address key in network byte order.
 * @out: Destination buffer for the domain.
 * @outlen: Length of @out in bytes.
 * @return: True when a mapping was found, otherwise false.
 * @note: The copied string is always bounded by @outlen.
 */
bool dns_map_lookup(__be32 ip, char *out, size_t outlen)
{
	struct dns_entry *entry;
	bool found = false;

	if (!out || !outlen)
		return false;

	spin_lock_bh(&dns_map_lock);
	entry = dns_map_find_locked(ip);
	if (entry) {
		strlcpy(out, entry->domain, outlen);
		entry->last_seen = ktime_get_real();
		found = true;
	}
	spin_unlock_bh(&dns_map_lock);

	return found;
}

/**
 * dns_map_seq_show() - Emit DNS cache rows into a seq_file.
 * @m: seq_file receiving rows.
 * @return: None.
 * @note: Timestamps are formatted by proc_interface helpers as raw ktime here
 * would couple this cache to presentation code, so seconds/nanoseconds are
 * emitted in ISO format locally.
 */
void dns_map_seq_show(struct seq_file *m)
{
	struct dns_entry *entry;
	struct timespec64 first;
	struct timespec64 last;
	struct tm tm_first;
	struct tm tm_last;
	char first_buf[PROC_TIME_BUF_LEN];
	char last_buf[PROC_TIME_BUF_LEN];
	unsigned int bucket;

	spin_lock_bh(&dns_map_lock);
	hash_for_each(dns_hash, bucket, entry, hnode) {
		first = ktime_to_timespec64(entry->first_seen);
		last = ktime_to_timespec64(entry->last_seen);
		time64_to_tm(first.tv_sec, 0, &tm_first);
		time64_to_tm(last.tv_sec, 0, &tm_last);
		snprintf(first_buf, sizeof(first_buf),
			 "%04ld-%02d-%02dT%02d:%02d:%02d.%09ldZ",
			 tm_first.tm_year + 1900, tm_first.tm_mon + 1,
			 tm_first.tm_mday, tm_first.tm_hour, tm_first.tm_min,
			 tm_first.tm_sec, first.tv_nsec);
		snprintf(last_buf, sizeof(last_buf),
			 "%04ld-%02d-%02dT%02d:%02d:%02d.%09ldZ",
			 tm_last.tm_year + 1900, tm_last.tm_mon + 1,
			 tm_last.tm_mday, tm_last.tm_hour, tm_last.tm_min,
			 tm_last.tm_sec, last.tv_nsec);
		seq_printf(m, "%pI4|%s|%s|%s|%u\n", &entry->ip,
			   entry->domain, first_buf, last_buf,
			   entry->query_count);
	}
	spin_unlock_bh(&dns_map_lock);
}

/**
 * dns_map_count() - Return the number of cached DNS mappings.
 * @return: Current DNS entry count.
 * @note: The value is sampled under the DNS cache spinlock.
 */
u32 dns_map_count(void)
{
	u32 count;

	spin_lock_bh(&dns_map_lock);
	count = dns_entries;
	spin_unlock_bh(&dns_map_lock);

	return count;
}

