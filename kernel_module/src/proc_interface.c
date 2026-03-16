#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#include "../include/traffic_analyzer.h"

#define PROC_NAME "traffic_analyzer"

static int traffic_show(struct seq_file *m, void *v)
{
    struct traffic_node *node;

    seq_printf(m, "PID PROCESS DEST_IP PORT BYTES\n");

    spin_lock_bh(&stats_lock);

    list_for_each_entry(node, &traffic_list, list)
    {
        seq_printf(m,
                   "%d %s %pI4 %u %llu\n",
                   node->entry.pid,
                   node->entry.comm,
                   &node->entry.dest_ip,
                   node->entry.port,
                   node->entry.bytes);
    }

    spin_unlock_bh(&stats_lock);

    return 0;
}

static int traffic_open(struct inode *inode, struct file *file)
{
    return single_open(file, traffic_show, NULL);
}

/* allow clearing stats from user space */
static ssize_t traffic_write(struct file *file,
                             const char __user *buffer,
                             size_t count,
                             loff_t *ppos)
{
    char cmd[16];

    if (count > sizeof(cmd) - 1)
        count = sizeof(cmd) - 1;

    if (copy_from_user(cmd, buffer, count))
        return -EFAULT;

    cmd[count] = '\0';

    if (strncmp(cmd, "clear", 5) == 0)
        stats_cleanup();

    return count;
}

static const struct proc_ops proc_fops = {
    .proc_open = traffic_open,
    .proc_read = seq_read,
    .proc_write = traffic_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

void proc_init(void)
{
    if (!proc_create(PROC_NAME, 0666, NULL, &proc_fops))
        printk(KERN_ERR "[traffic_analyzer] failed to create /proc entry\n");
}

void proc_cleanup(void)
{
    remove_proc_entry(PROC_NAME, NULL);
}