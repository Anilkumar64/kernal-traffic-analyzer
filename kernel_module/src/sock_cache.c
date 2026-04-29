/**
 * @file sock_cache.c
 * @brief Socket pointer to PID LRU cache.
 * @details Packet attribution first tries the skb socket pointer. This cache
 * maps stable sock pointers to live PIDs under a spinlock, evicting the least
 * recently used entry at capacity and removing entries whose process has died.
 * @author Kernel Traffic Analyzer Project
 * @license GPL-2.0
 */

#include <linux/hashtable.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include "../include/kta_api.h"

static DEFINE_HASHTABLE(sock_hash, SOCK_CACHE_HASH_BITS);
static DEFINE_SPINLOCK(sock_cache_lock);
static u32 sock_cache_entries;

/**
 * kta_pid_is_alive() - Check whether a PID currently maps to a task.
 * @pid: Numeric PID to validate.
 * @return: True when the PID is live, otherwise false.
 * @note: PID zero is treated as unresolved and therefore not alive.
 */
static bool kta_pid_is_alive(pid_t pid)
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
 * sock_cache_init() - Initialize the socket cache.
 * @return: Zero on success.
 * @note: Storage is allocated per inserted entry.
 */
int sock_cache_init(void)
{
	hash_init(sock_hash);
	sock_cache_entries = 0;
	return 0;
}

/**
 * sock_cache_exit() - Free all socket cache entries.
 * @return: None.
 * @note: Packet hooks must be unregistered before teardown.
 */
void sock_cache_exit(void)
{
	struct sock_cache_entry *entry;
	struct hlist_node *tmp;
	unsigned int bucket;

	spin_lock_bh(&sock_cache_lock);
	hash_for_each_safe(sock_hash, bucket, tmp, entry, hnode) {
		hash_del(&entry->hnode);
		kfree(entry);
	}
	sock_cache_entries = 0;
	spin_unlock_bh(&sock_cache_lock);
}

/**
 * sock_cache_key() - Compute a hash key for a sock pointer.
 * @sk: Socket pointer used as key.
 * @return: Unsigned hash key derived from the pointer value.
 * @note: The hash table macro applies the bucket mask.
 */
static unsigned long sock_cache_key(const struct sock *sk)
{
	return (unsigned long)sk;
}

/**
 * sock_cache_evict_lru_locked() - Evict the least recently accessed entry.
 * @return: None.
 * @note: Caller must hold sock_cache_lock.
 */
static void sock_cache_evict_lru_locked(void)
{
	struct sock_cache_entry *entry;
	struct sock_cache_entry *oldest = NULL;
	unsigned int bucket;

	hash_for_each(sock_hash, bucket, entry, hnode) {
		if (!oldest || time_before(entry->accessed, oldest->accessed))
			oldest = entry;
	}
	if (oldest) {
		hash_del(&oldest->hnode);
		kfree(oldest);
		if (sock_cache_entries)
			sock_cache_entries--;
	}
}

/**
 * sock_cache_lookup() - Resolve a sock pointer to a live PID.
 * @sk: Socket pointer from an skb.
 * @return: Live PID on hit, otherwise zero.
 * @note: Dead-PID entries are invalidated during lookup.
 */
pid_t sock_cache_lookup(const struct sock *sk)
{
	struct sock_cache_entry *entry;
	pid_t pid = 0;

	if (!sk)
		return 0;

	spin_lock_bh(&sock_cache_lock);
	hash_for_each_possible(sock_hash, entry, hnode, sock_cache_key(sk)) {
		if (entry->sk != sk)
			continue;
		if (!kta_pid_is_alive(entry->pid)) {
			hash_del(&entry->hnode);
			kfree(entry);
			if (sock_cache_entries)
				sock_cache_entries--;
			break;
		}
		entry->accessed = jiffies;
		pid = entry->pid;
		break;
	}
	spin_unlock_bh(&sock_cache_lock);

	return pid;
}

/**
 * sock_cache_store() - Store a sock pointer to PID mapping.
 * @sk: Socket pointer key.
 * @pid: PID value to cache.
 * @return: None.
 * @note: Uses GFP_ATOMIC because the caller may be in Netfilter context.
 */
void sock_cache_store(const struct sock *sk, pid_t pid)
{
	struct sock_cache_entry *entry;

	if (!sk || pid <= 0 || !kta_pid_is_alive(pid))
		return;

	spin_lock_bh(&sock_cache_lock);
	hash_for_each_possible(sock_hash, entry, hnode, sock_cache_key(sk)) {
		if (entry->sk == sk) {
			entry->pid = pid;
			entry->accessed = jiffies;
			spin_unlock_bh(&sock_cache_lock);
			return;
		}
	}

	if (sock_cache_entries >= MAX_SOCK_CACHE_ENTRIES)
		sock_cache_evict_lru_locked();

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		spin_unlock_bh(&sock_cache_lock);
		pr_err("kta: sock_cache: allocation failed\n");
		return;
	}
	entry->sk = sk;
	entry->pid = pid;
	entry->accessed = jiffies;
	hash_add(sock_hash, &entry->hnode, sock_cache_key(sk));
	sock_cache_entries++;
	spin_unlock_bh(&sock_cache_lock);
}

/**
 * sock_cache_invalidate() - Remove a sock pointer cache entry.
 * @sk: Socket pointer to invalidate.
 * @return: None.
 * @note: Safe to call even when @sk is absent.
 */
void sock_cache_invalidate(const struct sock *sk)
{
	struct sock_cache_entry *entry;
	struct hlist_node *tmp;

	if (!sk)
		return;

	spin_lock_bh(&sock_cache_lock);
	hash_for_each_possible_safe(sock_hash, entry, tmp, hnode,
				    sock_cache_key(sk)) {
		if (entry->sk == sk) {
			hash_del(&entry->hnode);
			kfree(entry);
			if (sock_cache_entries)
				sock_cache_entries--;
			break;
		}
	}
	spin_unlock_bh(&sock_cache_lock);
}

