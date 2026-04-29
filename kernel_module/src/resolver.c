/**
 * @file resolver.c
 * @brief Asynchronous flow-to-PID resolver.
 * @details Hook-time attribution cannot sleep, so unresolved flow keys are
 * queued to system_wq. Worker jobs inspect /proc/net socket tables to find a
 * matching inode and then scan task file tables for the owning process before
 * updating inode and flow caches.
 * @author Kernel Traffic Analyzer Project
 * @license GPL-2.0
 */

#include <linux/atomic.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include "../include/kta_api.h"

struct resolver_work {
	struct work_struct work;
	struct flow_key key;
};

static atomic_t resolver_inflight = ATOMIC_INIT(0);

/**
 * resolver_init() - Initialize async resolver state.
 * @return: Zero on success.
 * @note: Work is queued on system_wq; no private workqueue is allocated.
 */
int resolver_init(void)
{
	atomic_set(&resolver_inflight, 0);
	return 0;
}

/**
 * resolver_exit() - Drain pending resolver work.
 * @return: None.
 * @note: Ensures queued jobs cannot update caches after teardown proceeds.
 */
void resolver_exit(void)
{
	flush_scheduled_work();
	atomic_set(&resolver_inflight, 0);
}

/**
 * resolver_parse_ipv4_hex() - Convert /proc/net/tcp IPv4 hex to __be32.
 * @hex: Parsed little-endian hex address.
 * @return: IPv4 address in network byte order.
 * @note: /proc/net/tcp prints IPv4 addresses as host-order hex words.
 */
static __be32 resolver_parse_ipv4_hex(unsigned int hex)
{
	return htonl(hex);
}

/**
 * resolver_parse_tcp_table() - Scan a /proc/net TCP table for a flow inode.
 * @path: Path to the proc table.
 * @key: Canonical flow key to match.
 * @inode: Destination inode when found.
 * @is_ipv6: True when parsing /proc/net/tcp6.
 * @return: True when an inode was found.
 * @note: The file is read into a bounded kernel buffer using kernel_read().
 */
static bool resolver_parse_tcp_table(const char *path, const struct flow_key *key,
				     unsigned long *inode, bool is_ipv6)
{
	struct file *file;
	char *buf;
	loff_t pos = 0;
	ssize_t read;
	size_t used = 0;
	bool found = false;

	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file))
		return false;

	buf = kzalloc(RESOLVER_MAX_FILE_BYTES, GFP_KERNEL);
	if (!buf) {
		filp_close(file, NULL);
		pr_err("kta: resolver: allocation failed reading %s\n", path);
		return false;
	}

	while (used + RESOLVER_READ_CHUNK < RESOLVER_MAX_FILE_BYTES) {
		read = kernel_read(file, buf + used, RESOLVER_READ_CHUNK, &pos);
		if (read <= 0)
			break;
		used += read;
	}
	buf[used] = '\0';

	{
		char *line = buf;
		char *next;

		while (line && *line) {
			unsigned int lip = 0;
			unsigned int rip = 0;
			unsigned int lp = 0;
			unsigned int rp = 0;
			unsigned long ino = 0;
			__be32 local_ip = 0;
			__be32 remote_ip = 0;
			struct flow_key candidate = { };
			char l6[PROC_NET_TCP6_HEX_LEN + 1];
			char r6[PROC_NET_TCP6_HEX_LEN + 1];

			next = strchr(line, '\n');
			if (next)
				*next++ = '\0';

			if (!is_ipv6) {
				if (sscanf(line,
					   " %*u: %x:%x %x:%x %*x %*s %*s %*s %*u %*u %lu",
					   &lip, &lp, &rip, &rp, &ino) >= 5) {
					local_ip = resolver_parse_ipv4_hex(lip);
					remote_ip = resolver_parse_ipv4_hex(rip);
				}
			} else {
				l6[0] = '\0';
				r6[0] = '\0';
				if (sscanf(line,
					   " %*u: %32s:%x %32s:%x %*x %*s %*s %*s %*u %*u %lu",
					   l6, &lp, r6, &rp, &ino) >= 5) {
					unsigned int llast = 0;
					unsigned int rlast = 0;

					sscanf(l6 + 24, "%x", &llast);
					sscanf(r6 + 24, "%x", &rlast);
					local_ip = htonl(llast);
					remote_ip = htonl(rlast);
				}
			}

			if (ino) {
				candidate.src_ip = local_ip;
				candidate.dst_ip = remote_ip;
				candidate.src_port = htons((u16)lp);
				candidate.dst_port = htons((u16)rp);
				candidate.protocol = IPPROTO_TCP;
				make_canonical(&candidate);
				if (memcmp(&candidate, key, sizeof(candidate)) == 0) {
					*inode = ino;
					found = true;
					break;
				}
			}

			line = next;
		}
	}

	kfree(buf);
	filp_close(file, NULL);
	return found;
}

/**
 * resolver_find_pid_by_inode() - Find a task with an fd pointing at an inode.
 * @inode: Socket inode to match.
 * @return: Owning PID when found, otherwise zero.
 * @note: This inspects task file tables under RCU and does not dereference
 * sk_socket->file.
 */
static pid_t resolver_find_pid_by_inode(unsigned long inode)
{
	struct task_struct *task;
	pid_t pid = 0;

	rcu_read_lock();
	for_each_process(task) {
		struct files_struct *files;
		struct fdtable *fdt;
		unsigned int fd;

		files = task->files;
		if (!files)
			continue;
		spin_lock(&files->file_lock);
		fdt = files_fdtable(files);
		for (fd = 0; fd < fdt->max_fds; fd++) {
			struct file *file = rcu_dereference_raw(fdt->fd[fd]);
			struct inode *ino;

			if (!file)
				continue;
			ino = file_inode(file);
			if (ino && ino->i_ino == inode) {
				pid = task_pid_nr(task);
				break;
			}
		}
		spin_unlock(&files->file_lock);
		if (pid)
			break;
	}
	rcu_read_unlock();

	return pid;
}

/**
 * resolver_worker() - Worker body for async flow resolution.
 * @work: Embedded work item.
 * @return: None.
 * @note: On success both inode and flow caches are updated.
 */
static void resolver_worker(struct work_struct *work)
{
	struct resolver_work *job = container_of(work, struct resolver_work, work);
	unsigned long inode = 0;
	pid_t pid = 0;

	if (resolver_parse_tcp_table("/proc/net/tcp", &job->key, &inode, false) ||
	    resolver_parse_tcp_table("/proc/net/tcp6", &job->key, &inode, true)) {
		pid = resolver_find_pid_by_inode(inode);
		if (pid > 0) {
			inode_cache_store(inode, pid);
			flow_cache_store(&job->key, pid);
		}
	}

	atomic_dec(&resolver_inflight);
	kfree(job);
}

/**
 * resolver_schedule() - Queue async resolution for a flow key.
 * @key: Canonical or non-canonical flow key.
 * @return: None.
 * @note: Requests are rate-limited by RESOLVER_MAX_INFLIGHT and flow backoff.
 */
void resolver_schedule(const struct flow_key *key)
{
	struct resolver_work *job;
	struct flow_key canonical;

	if (!key || !flow_cache_should_scan(key))
		return;
	if (atomic_inc_return(&resolver_inflight) > RESOLVER_MAX_INFLIGHT) {
		atomic_dec(&resolver_inflight);
		return;
	}

	job = kzalloc(sizeof(*job), GFP_ATOMIC);
	if (!job) {
		atomic_dec(&resolver_inflight);
		pr_err("kta: resolver: work allocation failed\n");
		return;
	}

	canonical = *key;
	make_canonical(&canonical);
	job->key = canonical;
	INIT_WORK(&job->work, resolver_worker);
	flow_cache_set_scanned(&canonical);
	queue_work(system_wq, &job->work);
}

