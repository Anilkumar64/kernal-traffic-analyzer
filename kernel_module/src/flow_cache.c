/**
 * @file flow_cache.c
 * @brief Canonical flow-key to PID cache with resolver backoff.
 * @details When socket and inode attribution miss, a normalized five-tuple can
 * still identify a process after asynchronous resolver work completes. The
 * cache also tracks whether a flow should be rescanned after a short interval
 * so long-lived sockets can recover from PID ownership changes.
 * @author Kernel Traffic Analyzer Project
 * @license GPL-2.0
 */

#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include "../include/kta_api.h"

static DEFINE_HASHTABLE(flow_hash, FLOW_CACHE_HASH_BITS);
static DEFINE_SPINLOCK(flow_cache_lock);
static u32 flow_cache_entries;

/**
 * flow_pid_is_alive() - Check whether a cached PID is live.
 * @pid: PID to test.
 * @return: True when @pid maps to a task.
 * @note: Used to avoid attributing packets to recycled or dead processes.
 */
static bool flow_pid_is_alive(pid_t pid)
{
	bool alive;

	if (pid <= 0)
		return false;

	rcu_read_lock();
	alive = pid_task(find_vpid(pid), PIDTYPE_PID) != NULL;
	rcu_read_unlock();

	return alive;
}

/**
 * flow_hash_key() - Hash a canonical flow key.
 * @key: Flow key to hash.
 * @return: jhash2 hash value.
 * @note: The key is copied and canonicalized before hashing.
 */
static u32 flow_hash_key(const struct flow_key *key)
{
	struct flow_key canonical = *key;

	make_canonical(&canonical);
	return jhash2((const u32 *)&canonical, sizeof(canonical) / sizeof(u32),
		      KTA_JHASH_INITVAL);
}

/**
 * flow_keys_equal() - Compare two flow keys after canonicalization.
 * @left: First key.
 * @right: Second key.
 * @return: True when keys describe the same bidirectional flow.
 * @note: Padding bytes are part of struct flow_key and are zeroed by callers.
 */
static bool flow_keys_equal(const struct flow_key *left,
			    const struct flow_key *right)
{
	struct flow_key a = *left;
	struct flow_key b = *right;

	make_canonical(&a);
	make_canonical(&b);
	return memcmp(&a, &b, sizeof(a)) == 0;
}

/**
 * flow_cache_init() - Initialize the flow cache.
 * @return: Zero on success.
 * @note: Entry storage is allocated on demand.
 */
int flow_cache_init(void)
{
	hash_init(flow_hash);
	flow_cache_entries = 0;
	return 0;
}

/**
 * flow_cache_exit() - Free all flow cache entries.
 * @return: None.
 * @note: Called after Netfilter hooks have been removed.
 */
void flow_cache_exit(void)
{
	struct flow_cache_entry *entry;
	struct hlist_node *tmp;
	unsigned int bucket;

	spin_lock_bh(&flow_cache_lock);
	hash_for_each_safe(flow_hash, bucket, tmp, entry, hnode) {
		hash_del(&entry->hnode);
		kfree(entry);
	}
	flow_cache_entries = 0;
	spin_unlock_bh(&flow_cache_lock);
}

/**
 * flow_cache_evict_lru_locked() - Evict the least recently used flow entry.
 * @return: None.
 * @note: Caller must hold flow_cache_lock.
 */
static void flow_cache_evict_lru_locked(void)
{
	struct flow_cache_entry *entry;
	struct flow_cache_entry *oldest = NULL;
	unsigned int bucket;

	hash_for_each(flow_hash, bucket, entry, hnode) {
		if (!oldest || time_before(entry->accessed, oldest->accessed))
			oldest = entry;
	}
	if (oldest) {
		hash_del(&oldest->hnode);
		kfree(oldest);
		if (flow_cache_entries)
			flow_cache_entries--;
	}
}

/**
 * flow_cache_lookup() - Resolve a flow key to a live PID.
 * @key: Flow key to look up.
 * @return: Live PID on hit, otherwise zero.
 * @note: All hash operations use canonicalized keys.
 */
pid_t flow_cache_lookup(const struct flow_key *key)
{
	struct flow_cache_entry *entry;
	u32 hash;
	pid_t pid = 0;

	if (!key)
		return 0;

	hash = flow_hash_key(key);
	spin_lock_bh(&flow_cache_lock);
	hash_for_each_possible(flow_hash, entry, hnode, hash) {
		if (!flow_keys_equal(&entry->key, key))
			continue;
		if (entry->pid <= 0) {
			pid = 0;
			break;
		}
		if (!flow_pid_is_alive(entry->pid)) {
			hash_del(&entry->hnode);
			kfree(entry);
			if (flow_cache_entries)
				flow_cache_entries--;
			break;
		}
		entry->accessed = jiffies;
		pid = entry->pid;
		break;
	}
	spin_unlock_bh(&flow_cache_lock);

	return pid;
}

/**
 * flow_cache_store() - Store a flow key to PID mapping.
 * @key: Flow key to cache.
 * @pid: PID to associate with @key.
 * @return: None.
 * @note: Uses GFP_ATOMIC because packet hooks may update recent attribution.
 */
void flow_cache_store(const struct flow_key *key, pid_t pid)
{
	struct flow_cache_entry *entry;
	struct flow_key canonical;
	u32 hash;

	if (!key || pid <= 0 || !flow_pid_is_alive(pid))
		return;

	canonical = *key;
	make_canonical(&canonical);
	hash = flow_hash_key(&canonical);

	spin_lock_bh(&flow_cache_lock);
	hash_for_each_possible(flow_hash, entry, hnode, hash) {
		if (flow_keys_equal(&entry->key, &canonical)) {
			entry->pid = pid;
			entry->should_scan = true;
			entry->accessed = jiffies;
			spin_unlock_bh(&flow_cache_lock);
			return;
		}
	}

	if (flow_cache_entries >= MAX_FLOW_CACHE_ENTRIES)
		flow_cache_evict_lru_locked();

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		spin_unlock_bh(&flow_cache_lock);
		pr_err("kta: flow_cache: allocation failed\n");
		return;
	}
	entry->key = canonical;
	entry->pid = pid;
	entry->should_scan = true;
	entry->accessed = jiffies;
	hash_add(flow_hash, &entry->hnode, hash);
	flow_cache_entries++;
	spin_unlock_bh(&flow_cache_lock);
}

/**
 * flow_cache_should_scan() - Decide whether async resolver work should run.
 * @key: Flow key to inspect.
 * @return: True when the flow should be scanned.
 * @note: Scanned entries become eligible again after FLOW_RESCAN_INTERVAL_SECS.
 */
bool flow_cache_should_scan(const struct flow_key *key)
{
	struct flow_cache_entry *entry;
	u32 hash;
	bool should = true;

	if (!key)
		return false;

	hash = flow_hash_key(key);
	spin_lock_bh(&flow_cache_lock);
	hash_for_each_possible(flow_hash, entry, hnode, hash) {
		if (!flow_keys_equal(&entry->key, key))
			continue;
		if (!entry->should_scan &&
		    time_after(jiffies, entry->accessed +
			       FLOW_RESCAN_INTERVAL_SECS * HZ))
			entry->should_scan = true;
		should = entry->should_scan;
		break;
	}
	spin_unlock_bh(&flow_cache_lock);

	return should;
}

/**
 * flow_cache_set_scanned() - Mark a flow as scanned by the resolver.
 * @key: Flow key that was scheduled or scanned.
 * @return: None.
 * @note: Missing entries are inserted with PID zero suppressed by design.
 */
void flow_cache_set_scanned(const struct flow_key *key)
{
	struct flow_cache_entry *entry;
	struct flow_key canonical;
	u32 hash;

	if (!key)
		return;

	canonical = *key;
	make_canonical(&canonical);
	hash = flow_hash_key(&canonical);
	spin_lock_bh(&flow_cache_lock);
	hash_for_each_possible(flow_hash, entry, hnode, hash) {
		if (flow_keys_equal(&entry->key, &canonical)) {
			entry->should_scan = false;
			entry->accessed = jiffies;
			spin_unlock_bh(&flow_cache_lock);
			return;
		}
	}

	if (flow_cache_entries >= MAX_FLOW_CACHE_ENTRIES)
		flow_cache_evict_lru_locked();

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		spin_unlock_bh(&flow_cache_lock);
		pr_err("kta: flow_cache: scan marker allocation failed\n");
		return;
	}
	entry->key = canonical;
	entry->pid = 0;
	entry->should_scan = false;
	entry->accessed = jiffies;
	hash_add(flow_hash, &entry->hnode, hash);
	flow_cache_entries++;
	spin_unlock_bh(&flow_cache_lock);
}
