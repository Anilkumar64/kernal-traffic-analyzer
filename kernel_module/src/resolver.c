#include <linux/rcupdate.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <net/sock.h>
#include "../include/cache.h"
#include "../include/inode_cache.h"
#include "../include/sock_cache.h"
#include "../include/exe_resolver.h"
#include "../include/resolver.h"
#include "../include/traffic_analyzer.h"

static struct workqueue_struct *resolver_wq;

#define RESOLVER_INFLIGHT_BITS 8
#define RESOLVER_INFLIGHT_BUCKETS (1U << RESOLVER_INFLIGHT_BITS)
#define RESOLVER_INFLIGHT_MAX 256
#define RESOLVER_QUEUE_MAX 128
#define MAX_RESOLVER_WORKERS 4

enum resolver_work_type
{
    RESOLVE_WORK_SOCKET = 1,
    RESOLVE_WORK_EXE = 2,
};

struct inflight_entry
{
    struct hlist_node node;
    unsigned long key;
};

static DEFINE_SPINLOCK(inflight_lock);
static struct hlist_head inflight[RESOLVER_INFLIGHT_BUCKETS];
static unsigned int inflight_count;
static atomic_t resolver_queue_depth = ATOMIC_INIT(0);
static atomic_t dropped_resolutions = ATOMIC_INIT(0);

static unsigned int inflight_bucket(unsigned long key)
{
    return hash_long(key, RESOLVER_INFLIGHT_BITS);
}

static unsigned long inflight_key(enum resolver_work_type type,
                                  unsigned long value)
{
    return (value << 2) ^ type;
}

static bool inflight_try_add(unsigned long key)
{
    struct inflight_entry *entry;
    unsigned int bucket = inflight_bucket(key);

    spin_lock(&inflight_lock);

    if (inflight_count >= RESOLVER_INFLIGHT_MAX ||
        atomic_read(&resolver_queue_depth) >= RESOLVER_QUEUE_MAX)
    {
        atomic_inc(&dropped_resolutions);
        spin_unlock(&inflight_lock);
        return false;
    }

    hlist_for_each_entry(entry, &inflight[bucket], node)
    {
        if (entry->key == key)
        {
            spin_unlock(&inflight_lock);
            return false;
        }
    }

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
    {
        atomic_inc(&dropped_resolutions);
        spin_unlock(&inflight_lock);
        return false;
    }

    entry->key = key;
    hlist_add_head(&entry->node, &inflight[bucket]);
    inflight_count++;
    atomic_inc(&resolver_queue_depth);

    spin_unlock(&inflight_lock);
    return true;
}

static void inflight_remove(unsigned long key)
{
    struct inflight_entry *entry;
    struct hlist_node *tmp;
    unsigned int bucket = inflight_bucket(key);

    spin_lock(&inflight_lock);

    hlist_for_each_entry_safe(entry, tmp, &inflight[bucket], node)
    {
        if (entry->key == key)
        {
            hlist_del(&entry->node);
            kfree(entry);
            if (inflight_count > 0)
                inflight_count--;
            atomic_dec_if_positive(&resolver_queue_depth);
            break;
        }
    }

    spin_unlock(&inflight_lock);
}

/* ================================================================
 * INODE SCAN
 * ================================================================ */
pid_t resolve_pid_from_inode(unsigned long ino)
{
    struct task_struct *task;
    pid_t found = 0;

    if (!ino)
        return 0;

    found = inode_cache_lookup(ino);
    if (found)
        return found;

    rcu_read_lock();

    for_each_process(task)
    {
        struct files_struct *files = task->files;
        struct fdtable *fdt;
        int i;

        if (!files)
            continue;

        spin_lock(&files->file_lock);

        fdt = files_fdtable(files);
        if (!fdt)
        {
            spin_unlock(&files->file_lock);
            continue;
        }

        for (i = 0; i < fdt->max_fds; i++)
        {
            struct file *f = fdt->fd[i];
            struct inode *fi;

            if (!f)
                continue;

            fi = file_inode(f);
            if (!fi)
                continue;

            if (fi->i_ino == ino)
            {
                found = task_pid_nr(task);
                spin_unlock(&files->file_lock);
                goto out;
            }
        }

        spin_unlock(&files->file_lock);
    }

out:
    rcu_read_unlock();

    if (found)
        inode_cache_insert(ino, found);

    return found;
}

/* ================================================================
 * FILE SCAN
 * ================================================================ */
pid_t resolve_pid_from_file(struct file *file)
{
    struct task_struct *task;
    pid_t found = 0;

    if (!file)
        return 0;

    found = cache_lookup(file);
    if (found)
        return found;

    if (file_inode(file))
    {
        unsigned long ino = file_inode(file)->i_ino;
        found = resolve_pid_from_inode(ino);
        if (found)
        {
            cache_insert(file, found);
            return found;
        }
    }

    rcu_read_lock();

    for_each_process(task)
    {
        struct files_struct *files = task->files;
        struct fdtable *fdt;
        int i;

        if (!files)
            continue;

        spin_lock(&files->file_lock);

        fdt = files_fdtable(files);
        if (!fdt)
        {
            spin_unlock(&files->file_lock);
            continue;
        }

        for (i = 0; i < fdt->max_fds; i++)
        {
            if (fdt->fd[i] == file)
            {
                found = task_pid_nr(task);
                spin_unlock(&files->file_lock);
                goto out_file;
            }
        }

        spin_unlock(&files->file_lock);
    }

out_file:
    rcu_read_unlock();

    if (found)
        cache_insert(file, found);

    return found;
}

/* ================================================================
 * SOCKET RESOLVE WORK ITEM
 * ================================================================ */
struct resolve_work
{
    struct work_struct work;
    unsigned long inflight_key;
    unsigned long ino;
    struct sock *sk;
    struct file *file;
};

static void resolve_work_fn(struct work_struct *work)
{
    struct resolve_work *rw =
        container_of(work, struct resolve_work, work);
    pid_t pid = 0;

    if (rw->ino)
        pid = resolve_pid_from_inode(rw->ino);
    if (!pid && rw->file)
        pid = resolve_pid_from_file(rw->file);

    if (pid)
    {
        if (rw->sk)
            sock_cache_insert(rw->sk, pid);
        if (rw->file)
            cache_insert(rw->file, pid);
        if (rw->ino)
            inode_cache_insert(rw->ino, pid);
    }

    inflight_remove(rw->inflight_key);
    kfree(rw);
}

void resolver_schedule(unsigned long ino, struct sock *sk, struct file *file)
{
    struct resolve_work *rw;
    unsigned long key_value = ino;
    unsigned long key;

    if (!resolver_wq)
        return;

    if (!key_value && file && file_inode(file))
        key_value = file_inode(file)->i_ino;
    if (!key_value)
        key_value = (unsigned long)sk;
    if (!key_value)
        return;

    key = inflight_key(RESOLVE_WORK_SOCKET, key_value);
    if (!inflight_try_add(key))
        return;

    rw = kmalloc(sizeof(*rw), GFP_ATOMIC);
    if (!rw)
    {
        inflight_remove(key);
        return;
    }

    INIT_WORK(&rw->work, resolve_work_fn);
    rw->inflight_key = key;
    rw->ino = ino;
    rw->sk = sk;
    rw->file = file;

    if (!queue_work(resolver_wq, &rw->work))
    {
        inflight_remove(key);
        kfree(rw);
    }
}

/* ================================================================
 * PHASE 3: EXE RESOLVE WORK ITEM
 *
 * Reads the full executable path for a PID from process context
 * (d_path can sleep) and inserts into exe_cache.
 * ================================================================ */
struct exe_work
{
    struct work_struct work;
    unsigned long inflight_key;
    pid_t pid;
};

static void exe_work_fn(struct work_struct *work)
{
    struct exe_work *ew = container_of(work, struct exe_work, work);
    char path[EXE_PATH_MAX];

    if (get_exe_path(ew->pid, path, sizeof(path)))
        exe_cache_insert(ew->pid, path);

    inflight_remove(ew->inflight_key);
    kfree(ew);
}

void resolver_schedule_exe(pid_t pid)
{
    struct exe_work *ew;
    unsigned long key;

    if (!resolver_wq || !pid)
        return;

    /* Don't queue if already cached */
    if (exe_cache_lookup(pid, NULL, 0))
        return;

    key = inflight_key(RESOLVE_WORK_EXE, (unsigned long)pid);
    if (!inflight_try_add(key))
        return;

    ew = kmalloc(sizeof(*ew), GFP_ATOMIC);
    if (!ew)
    {
        inflight_remove(key);
        return;
    }

    INIT_WORK(&ew->work, exe_work_fn);
    ew->inflight_key = key;
    ew->pid = pid;

    if (!queue_work(resolver_wq, &ew->work))
    {
        inflight_remove(key);
        kfree(ew);
    }
}

/* ================================================================
 * INIT / CLEANUP
 * ================================================================ */
void resolver_init(void)
{
    unsigned int i;

    for (i = 0; i < RESOLVER_INFLIGHT_BUCKETS; i++)
        INIT_HLIST_HEAD(&inflight[i]);
    inflight_count = 0;
    atomic_set(&resolver_queue_depth, 0);
    atomic_set(&dropped_resolutions, 0);

    resolver_wq = alloc_workqueue("ta_resolver",
                                  WQ_UNBOUND | WQ_MEM_RECLAIM,
                                  MAX_RESOLVER_WORKERS);
    if (!resolver_wq)
        printk(KERN_ERR "[TA] Failed to create resolver workqueue\n");
}

void resolver_cleanup(void)
{
    if (resolver_wq)
    {
        flush_workqueue(resolver_wq);
        destroy_workqueue(resolver_wq);
        resolver_wq = NULL;
    }
}
