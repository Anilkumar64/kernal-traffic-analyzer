#include <linux/rcupdate.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <net/sock.h>
#include "../include/cache.h"
#include "../include/inode_cache.h"
#include "../include/sock_cache.h"
#include "../include/exe_resolver.h"
#include "../include/resolver.h"
#include "../include/traffic_analyzer.h"

static struct workqueue_struct *resolver_wq;

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

    kfree(rw);
}

void resolver_schedule(unsigned long ino, struct sock *sk, struct file *file)
{
    struct resolve_work *rw;

    if (!resolver_wq)
        return;

    rw = kmalloc(sizeof(*rw), GFP_ATOMIC);
    if (!rw)
        return;

    INIT_WORK(&rw->work, resolve_work_fn);
    rw->ino = ino;
    rw->sk = sk;
    rw->file = file;

    queue_work(resolver_wq, &rw->work);
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
    pid_t pid;
};

static void exe_work_fn(struct work_struct *work)
{
    struct exe_work *ew = container_of(work, struct exe_work, work);
    char path[EXE_PATH_MAX];

    if (get_exe_path(ew->pid, path, sizeof(path)))
        exe_cache_insert(ew->pid, path);

    kfree(ew);
}

void resolver_schedule_exe(pid_t pid)
{
    struct exe_work *ew;

    if (!resolver_wq || !pid)
        return;

    /* Don't queue if already cached */
    if (exe_cache_lookup(pid, NULL, 0))
        return;

    ew = kmalloc(sizeof(*ew), GFP_ATOMIC);
    if (!ew)
        return;

    INIT_WORK(&ew->work, exe_work_fn);
    ew->pid = pid;

    queue_work(resolver_wq, &ew->work);
}

/* ================================================================
 * INIT / CLEANUP
 * ================================================================ */
void resolver_init(void)
{
    resolver_wq = alloc_workqueue("ta_resolver",
                                  WQ_UNBOUND | WQ_MEM_RECLAIM, 4);
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