/**
 * @file inode_cache.c
 * @brief Socket inode to PID LRU cache.
 * @details Resolver work can discover a process by socket inode. This cache
 * preserves those results for hook-time lookups, validates PID liveness on
 * every hit, and uses LRU eviction when the fixed entry cap is reached.
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

static DEFINE_HASHTABLE(inode_hash, INODE_CACHE_HASH_BITS);
static DEFINE_SPINLOCK(inode_cache_lock);
static u32 inode_cache_entries;

/**
 * inode_pid_is_alive() - Check whether a cached PID is live.
 * @pid: PID to test.
 * @return: True when @pid maps to a task.
 * @note: PID zero is unresolved and returns false.
 */
static bool inode_pid_is_alive(pid_t pid)
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
 * inode_cache_init() - Initialize the inode cache.
 * @return: Zero on success.
 * @note: Hash table storage is static.
 */
int inode_cache_init(void)
{
	hash_init(inode_hash);
	inode_cache_entries = 0;
	return 0;
}

/**
 * inode_cache_exit() - Free all inode cache entries.
 * @return: None.
 * @note: Called during module teardown after hooks are removed.
 */
void inode_cache_exit(void)
{
	struct inode_cache_entry *entry;
	struct hlist_node *tmp;
	unsigned int bucket;

	spin_lock_bh(&inode_cache_lock);
	hash_for_each_safe(inode_hash, bucket, tmp, entry, hnode) {
		hash_del(&entry->hnode);
		kfree(entry);
	}
	inode_cache_entries = 0;
	spin_unlock_bh(&inode_cache_lock);
}

/**
 * inode_cache_evict_lru_locked() - Evict the least recently used inode entry.
 * @return: None.
 * @note: Caller must hold inode_cache_lock.
 */
static void inode_cache_evict_lru_locked(void)
{
	struct inode_cache_entry *entry;
	struct inode_cache_entry *oldest = NULL;
	unsigned int bucket;

	hash_for_each(inode_hash, bucket, entry, hnode) {
		if (!oldest || time_before(entry->accessed, oldest->accessed))
			oldest = entry;
	}
	if (oldest) {
		hash_del(&oldest->hnode);
		kfree(oldest);
		if (inode_cache_entries)
			inode_cache_entries--;
	}
}

/**
 * inode_cache_lookup() - Resolve a socket inode to a live PID.
 * @ino: Socket inode number.
 * @return: Live PID on hit, otherwise zero.
 * @note: Dead-PID entries are removed before returning a miss.
 */
pid_t inode_cache_lookup(unsigned long ino)
{
	struct inode_cache_entry *entry;
	pid_t pid = 0;

	if (!ino)
		return 0;

	spin_lock_bh(&inode_cache_lock);
	hash_for_each_possible(inode_hash, entry, hnode, ino) {
		if (entry->inode != ino)
			continue;
		if (!inode_pid_is_alive(entry->pid)) {
			hash_del(&entry->hnode);
			kfree(entry);
			if (inode_cache_entries)
				inode_cache_entries--;
			break;
		}
		entry->accessed = jiffies;
		pid = entry->pid;
		break;
	}
	spin_unlock_bh(&inode_cache_lock);

	return pid;
}

/**
 * inode_cache_store() - Store a socket inode to PID mapping.
 * @ino: Socket inode number.
 * @pid: PID to cache.
 * @return: None.
 * @note: Uses GFP_ATOMIC because resolver results may race hook lookups.
 */
void inode_cache_store(unsigned long ino, pid_t pid)
{
	struct inode_cache_entry *entry;

	if (!ino || pid <= 0 || !inode_pid_is_alive(pid))
		return;

	spin_lock_bh(&inode_cache_lock);
	hash_for_each_possible(inode_hash, entry, hnode, ino) {
		if (entry->inode == ino) {
			entry->pid = pid;
			entry->accessed = jiffies;
			spin_unlock_bh(&inode_cache_lock);
			return;
		}
	}

	if (inode_cache_entries >= MAX_INODE_CACHE_ENTRIES)
		inode_cache_evict_lru_locked();

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		spin_unlock_bh(&inode_cache_lock);
		pr_err("kta: inode_cache: allocation failed\n");
		return;
	}
	entry->inode = ino;
	entry->pid = pid;
	entry->accessed = jiffies;
	hash_add(inode_hash, &entry->hnode, ino);
	inode_cache_entries++;
	spin_unlock_bh(&inode_cache_lock);
}

