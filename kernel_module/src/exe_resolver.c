/**
 * @file exe_resolver.c
 * @brief PID executable path resolver with TTL cache.
 * @details Executable resolution can sleep and is therefore isolated from the
 * hot packet path. The cache stores /proc/<pid>/exe d_path results for a short
 * TTL, handles dead processes and kernel threads gracefully, and bounds all
 * string copies for /proc consumers.
 * @author Kernel Traffic Analyzer Project
 * @license GPL-2.0
 */

#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include "../include/kta_api.h"

static DEFINE_HASHTABLE(exe_hash, EXE_CACHE_HASH_BITS);
static DEFINE_SPINLOCK(exe_cache_lock);
static u32 exe_cache_entries;

/**
 * exe_cache_init() - Initialize executable path cache state.
 * @return: Zero on success.
 * @note: Entries are allocated only after successful or meaningful lookups.
 */
int exe_cache_init(void)
{
	hash_init(exe_hash);
	exe_cache_entries = 0;
	return 0;
}

/**
 * exe_cache_exit() - Free all executable cache entries.
 * @return: None.
 * @note: Called when no /proc readers can use this module state.
 */
void exe_cache_exit(void)
{
	struct exe_cache_entry *entry;
	struct hlist_node *tmp;
	unsigned int bucket;

	spin_lock_bh(&exe_cache_lock);
	hash_for_each_safe(exe_hash, bucket, tmp, entry, hnode) {
		hash_del(&entry->hnode);
		kfree(entry);
	}
	exe_cache_entries = 0;
	spin_unlock_bh(&exe_cache_lock);
}

/**
 * exe_cache_evict_one_locked() - Evict one expired or oldest executable entry.
 * @return: None.
 * @note: Caller must hold exe_cache_lock.
 */
static void exe_cache_evict_one_locked(void)
{
	struct exe_cache_entry *entry;
	struct exe_cache_entry *oldest = NULL;
	unsigned int bucket;

	hash_for_each(exe_hash, bucket, entry, hnode) {
		if (!oldest ||
		    time_before(entry->cached_jiffies, oldest->cached_jiffies))
			oldest = entry;
	}
	if (oldest) {
		hash_del(&oldest->hnode);
		kfree(oldest);
		if (exe_cache_entries)
			exe_cache_entries--;
	}
}

/**
 * exe_cache_lookup_locked() - Look up a valid executable cache entry.
 * @pid: PID to resolve.
 * @out: Destination path buffer.
 * @outlen: Destination buffer length.
 * @return: True on valid cache hit.
 * @note: Expired hits are removed before returning false.
 */
static bool exe_cache_lookup_locked(pid_t pid, char *out, size_t outlen)
{
	struct exe_cache_entry *entry;
	struct hlist_node *tmp;

	hash_for_each_possible_safe(exe_hash, entry, tmp, hnode, (u32)pid) {
		if (entry->pid != pid)
			continue;
		if (time_after(jiffies,
			       entry->cached_jiffies + EXE_CACHE_TTL_SECS * HZ)) {
			hash_del(&entry->hnode);
			kfree(entry);
			if (exe_cache_entries)
				exe_cache_entries--;
			return false;
		}
		strlcpy(out, entry->path, outlen);
		return true;
	}

	return false;
}

/**
 * exe_cache_store() - Store a PID executable path.
 * @pid: PID key.
 * @path: Path string to cache.
 * @return: None.
 * @note: Caller may pass "unknown" for graceful negative caching.
 */
static void exe_cache_store(pid_t pid, const char *path)
{
	struct exe_cache_entry *entry;

	if (pid <= 0 || !path)
		return;

	spin_lock_bh(&exe_cache_lock);
	hash_for_each_possible(exe_hash, entry, hnode, (u32)pid) {
		if (entry->pid == pid) {
			strlcpy(entry->path, path, sizeof(entry->path));
			entry->cached_jiffies = jiffies;
			spin_unlock_bh(&exe_cache_lock);
			return;
		}
	}

	if (exe_cache_entries >= MAX_EXE_CACHE_ENTRIES)
		exe_cache_evict_one_locked();

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		spin_unlock_bh(&exe_cache_lock);
		pr_err("kta: exe_resolver: allocation failed\n");
		return;
	}
	entry->pid = pid;
	strlcpy(entry->path, path, sizeof(entry->path));
	entry->cached_jiffies = jiffies;
	hash_add(exe_hash, &entry->hnode, (u32)pid);
	exe_cache_entries++;
	spin_unlock_bh(&exe_cache_lock);
}

/**
 * exe_cache_get() - Resolve and cache a PID executable path.
 * @pid: PID to resolve.
 * @out: Destination buffer.
 * @outlen: Destination buffer length.
 * @return: None.
 * @note: On cache miss this may sleep, so callers must avoid hook/atomic paths.
 */
void exe_cache_get(pid_t pid, char *out, size_t outlen)
{
	struct path exe_path;
	char proc_path[64];
	char *page;
	char *resolved;
	int ret;

	if (!out || !outlen)
		return;
	strlcpy(out, "unknown", outlen);
	if (pid <= 0)
		return;

	spin_lock_bh(&exe_cache_lock);
	if (exe_cache_lookup_locked(pid, out, outlen)) {
		spin_unlock_bh(&exe_cache_lock);
		return;
	}
	spin_unlock_bh(&exe_cache_lock);

	if (in_atomic() || irqs_disabled())
		return;

	snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
	ret = kern_path(proc_path, LOOKUP_FOLLOW, &exe_path);
	if (ret) {
		if (ret != -ESRCH && ret != -ENOENT)
			pr_err("kta: exe_resolver: kern_path failed for pid %d: %d\n",
			       pid, ret);
		exe_cache_store(pid, "unknown");
		return;
	}

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page) {
		path_put(&exe_path);
		pr_err("kta: exe_resolver: path buffer allocation failed\n");
		return;
	}

	resolved = d_path(&exe_path, page, PAGE_SIZE);
	if (IS_ERR(resolved)) {
		pr_err("kta: exe_resolver: d_path failed for pid %d\n", pid);
		strlcpy(out, "unknown", outlen);
		exe_cache_store(pid, "unknown");
	} else {
		strlcpy(out, resolved, outlen);
		exe_cache_store(pid, resolved);
	}

	free_page((unsigned long)page);
	path_put(&exe_path);
}

