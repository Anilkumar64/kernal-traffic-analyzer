#ifndef _RESOLVER_H
#define _RESOLVER_H

#include <linux/types.h>
#include <linux/fs.h>
#include <net/sock.h>

pid_t resolve_pid_from_file(struct file *file);
pid_t resolve_pid_from_inode(unsigned long ino);

/* Schedule async PID resolution (socket scan) */
void resolver_schedule(unsigned long ino, struct sock *sk,
                       struct file *file);

/* PHASE 3: Schedule async exe path resolution */
void resolver_schedule_exe(pid_t pid);

void resolver_init(void);
void resolver_cleanup(void);

#endif /* _RESOLVER_H */