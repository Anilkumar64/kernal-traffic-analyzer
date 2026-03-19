#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/file.h> /* fput() */
#include <linux/dcache.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/rcupdate.h>
#include <linux/pid.h>
#include "../include/exe_resolver.h"
#include "../include/traffic_analyzer.h"

/* ================================================================
 * EXE PATH READER
 *
 * task->mm->exe_file is the struct file* for the running binary.
 * d_path() walks the dentry tree to produce the full path string.
 *
 * get_mm_exe_file() was removed from exported symbols in kernel 6.7.
 * On 6.8 we read mm->exe_file directly under rcu_read_lock() and
 * bump its refcount with get_file() before dropping the lock.
 *
 * This function must run in process context (workqueue thread) —
 * d_path() can sleep via dentry cache operations.
 * ================================================================ */
bool get_exe_path(pid_t pid, char *buf, size_t bufsz)
{
    struct pid *p;
    struct task_struct *task;
    struct mm_struct *mm = NULL;
    struct file *exe_file = NULL;
    char *tmp;
    char *path;
    bool ok = false;

    if (!buf || !bufsz)
        return false;

    buf[0] = '\0';

    /* ---- locate task and get a stable mm reference ---- */
    rcu_read_lock();

    p = find_get_pid(pid);
    if (!p)
        goto out_rcu;

    task = pid_task(p, PIDTYPE_PID);
    put_pid(p);

    if (!task)
        goto out_rcu;

    /*
     * get_task_mm() bumps mm->mm_users so the mm stays alive
     * after we drop the RCU lock.
     */
    mm = get_task_mm(task);

out_rcu:
    rcu_read_unlock();

    if (!mm)
        return false;

    /*
     * Read mm->exe_file under rcu_read_lock and bump its refcount
     * with get_file() so it stays alive for d_path().
     *
     * get_mm_exe_file() is no longer exported in kernel ≥ 6.7 so we
     * replicate its logic: lock RCU, read the pointer, get_file().
     */
    rcu_read_lock();
    exe_file = rcu_dereference(mm->exe_file);
    if (exe_file)
        exe_file = get_file(exe_file); /* bumps f_count */
    rcu_read_unlock();

    mmput(mm);

    if (!exe_file)
        return false;

    /* d_path() writes backwards into tmp; result ptr is inside tmp */
    tmp = kmalloc(bufsz, GFP_KERNEL);
    if (!tmp)
    {
        fput(exe_file);
        return false;
    }

    path = d_path(&exe_file->f_path, tmp, bufsz);
    fput(exe_file);

    if (!IS_ERR(path))
    {
        strscpy(buf, path, bufsz);
        ok = true;
    }

    kfree(tmp);
    return ok;
}

/* ================================================================
 * EXE CACHE — PID → path hash table
 *
 * exe paths are expensive to read.  We cache them so repeated
 * packets for the same process don't re-walk the dentry tree.
 *
 * Invalidation: when pid_is_alive() returns false for a cached PID,
 * the caller in packet_parser removes it via exe_cache_invalidate().
 * ================================================================ */
#define EXE_CACHE_BITS 8

struct exe_entry
{
    pid_t pid;
    char path[EXE_PATH_MAX];
    struct hlist_node node;
};

static DEFINE_HASHTABLE(exe_cache, EXE_CACHE_BITS);
static DEFINE_SPINLOCK(exe_cache_lock);

void exe_cache_init(void)
{
    hash_init(exe_cache);
}

void exe_cache_insert(pid_t pid, const char *path)
{
    struct exe_entry *entry;

    if (!pid || !path || !path[0])
        return;

    /* Don't insert duplicates */
    if (exe_cache_lookup(pid, NULL, 0))
        return;

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return;

    entry->pid = pid;
    strscpy(entry->path, path, EXE_PATH_MAX);

    spin_lock(&exe_cache_lock);
    hash_add(exe_cache, &entry->node, (unsigned long)pid);
    spin_unlock(&exe_cache_lock);
}

bool exe_cache_lookup(pid_t pid, char *buf, size_t bufsz)
{
    struct exe_entry *entry;
    bool found = false;

    spin_lock(&exe_cache_lock);

    hash_for_each_possible(exe_cache, entry, node, (unsigned long)pid)
    {
        if (entry->pid != pid)
            continue;
        if (buf && bufsz)
            strscpy(buf, entry->path, bufsz);
        found = true;
        break;
    }

    spin_unlock(&exe_cache_lock);
    return found;
}

void exe_cache_invalidate(pid_t pid)
{
    struct exe_entry *entry;
    struct hlist_node *tmp;

    spin_lock(&exe_cache_lock);

    hash_for_each_possible_safe(exe_cache, entry, tmp, node, (unsigned long)pid)
    {
        if (entry->pid == pid)
        {
            hash_del(&entry->node);
            kfree(entry);
            break;
        }
    }

    spin_unlock(&exe_cache_lock);
}

void exe_cache_cleanup(void)
{
    struct exe_entry *entry;
    struct hlist_node *tmp;
    int bkt;

    spin_lock(&exe_cache_lock);

    hash_for_each_safe(exe_cache, bkt, tmp, entry, node)
    {
        hash_del(&entry->node);
        kfree(entry);
    }

    spin_unlock(&exe_cache_lock);
}