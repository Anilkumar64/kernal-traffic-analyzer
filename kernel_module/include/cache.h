#ifndef _CACHE_H
#define _CACHE_H

#include <linux/types.h>
#include <linux/fs.h>

void cache_init(void);
pid_t cache_lookup(struct file *file);
void cache_insert(struct file *file, pid_t pid);
void cache_cleanup(void);

#endif /* _CACHE_H */
