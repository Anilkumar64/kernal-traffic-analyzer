#ifndef _SOCK_CACHE_H
#define _SOCK_CACHE_H

#include <linux/types.h>
#include <net/sock.h>

void sock_cache_init(void);
void sock_cache_cleanup(void);
void sock_cache_insert(struct sock *sk, pid_t pid);
pid_t sock_cache_lookup(struct sock *sk);

#endif /* _SOCK_CACHE_H */