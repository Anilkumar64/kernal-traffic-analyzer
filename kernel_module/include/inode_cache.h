#ifndef _INODE_CACHE_H
#define _INODE_CACHE_H

#include <linux/types.h>

/*
 * inode_cache — maps socket inode numbers to PIDs.
 *
 * Inode numbers are stable for the lifetime of the socket (unlike file
 * pointers which can change after dup2/fork).  Caching by inode lets us
 * skip the full for_each_process scan on repeated packets for the same
 * socket without needing a struct sock * reference.
 *
 * TTL: same as sock_cache (60 s).  Entries are evicted on lookup miss
 * or on explicit cleanup.
 */

void inode_cache_init(void);
void inode_cache_cleanup(void);
pid_t inode_cache_lookup(unsigned long ino);
void inode_cache_insert(unsigned long ino, pid_t pid);
void inode_cache_invalidate(unsigned long ino); /* call on socket close */

#endif /* _INODE_CACHE_H */