#ifndef _EXE_RESOLVER_H
#define _EXE_RESOLVER_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/file.h>
#include "../include/traffic_analyzer.h"

/*
 * get_exe_path — read the full executable path for a PID.
 *
 * Reads task->mm->exe_file which is the struct file * backing the
 * running executable.  d_path() converts it to a string.
 *
 * Must be called from process context (workqueue), NOT from softirq.
 * Returns true on success, false if path could not be read.
 *
 * buf must be at least EXE_PATH_MAX bytes.
 */
bool get_exe_path(pid_t pid, char *buf, size_t bufsz);

/*
 * exe_cache — maps PID → exe path.
 *
 * exe paths are expensive to read (d_path + dentry walk).
 * We cache them keyed by PID.  Entries are invalidated when the
 * PID is recycled (detected via pid_is_alive check in packet_parser).
 */
void exe_cache_init(void);
void exe_cache_cleanup(void);
void exe_cache_insert(pid_t pid, const char *path);
bool exe_cache_lookup(pid_t pid, char *buf, size_t bufsz);
void exe_cache_invalidate(pid_t pid);

#endif /* _EXE_RESOLVER_H */