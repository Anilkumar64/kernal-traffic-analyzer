#ifndef _CACHE_H
#define _CACHE_H

#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/fs.h>

#define CACHE_BITS 10

struct file_pid_map
{
    struct file *file;
    pid_t pid;
    struct hlist_node node;
};

/*
 * FIX: DECLARE_HASHTABLE expands to a full variable definition
 * (struct hlist_head name[1 << bits]).  Placing it in a header means
 * every translation unit that includes cache.h emits its own copy of
 * the array → multiple-definition linker error.
 *
 * Rule:  DEFINE_HASHTABLE  in exactly one .c  (cache.c)
 *        extern declaration here in the header
 */
extern struct hlist_head file_pid_cache[1 << CACHE_BITS];

void cache_init(void);
pid_t cache_lookup(struct file *file);
void cache_insert(struct file *file, pid_t pid);
void cache_cleanup(void); /* FIX: was missing */

#endif /* _CACHE_H */