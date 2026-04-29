/**
 * @file packet_parser.c
 * @brief Netfilter packet dissector and PID attribution coordinator.
 * @details Packets are parsed without sleeping, supporting IPv4, IPv6 extension
 * header walking, TCP state derivation, UDP flow tracking, and four-tier PID
 * attribution through socket, inode, flow, and asynchronous resolver caches.
 * @author Kernel Traffic Analyzer Project
 * @license GPL-2.0
 */

#include <linux/cred.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include "../include/kta_api.h"

/**
 * make_canonical() - Normalize a flow key for bidirectional matching.
 * @key: Flow key to normalize in place.
 * @return: None.
 * @note: Lower IPv4 value is stored as src; ports are swapped with addresses.
 */
void make_canonical(struct flow_key *key)
{
	if (!key)
		return;
	if (ntohl(key->src_ip) > ntohl(key->dst_ip)) {
		__be32 ip = key->src_ip;
		__be16 port = key->src_port;

		key->src_ip = key->dst_ip;
		key->src_port = key->dst_port;
		key->dst_ip = ip;
		key->dst_port = port;
	}
}

/**
 * parser_task_name() - Resolve a task name for a PID without sleeping.
 * @pid: PID to inspect.
 * @out: Destination process-name buffer.
 * @outlen: Destination buffer length.
 * @return: None.
 * @note: Falls back to current->comm or "unknown" when unresolved.
 */
static void parser_task_name(pid_t pid, char *out, size_t outlen)
{
	struct task_struct *task;

	if (!out || !outlen)
		return;
	strlcpy(out, "unknown", outlen);
	if (pid <= 0) {
		if (current)
			strlcpy(out, current->comm, outlen);
		return;
	}

	rcu_read_lock();
	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (task)
		strlcpy(out, task->comm, outlen);
	rcu_read_unlock();
}

/**
 * parser_uid_from_sock() - Determine packet owner UID.
 * @sk: Socket pointer from skb.
 * @return: Numeric UID.
 * @note: Falls back to current_uid() when no socket UID is available.
 */
static uid_t parser_uid_from_sock(const struct sock *sk)
{
	if (sk)
		return from_kuid(&init_user_ns, sk->sk_uid);
	return from_kuid(&init_user_ns, current_uid());
}

/**
 * resolve_pid_4tier() - Resolve a flow PID using socket, inode, flow, resolver.
 * @key: Canonical flow key.
 * @sk: Socket pointer from skb, possibly NULL.
 * @return: PID on synchronous hit, otherwise zero.
 * @note: Tier four schedules async work and returns unresolved for this packet.
 */
pid_t resolve_pid_4tier(const struct flow_key *key, const struct sock *sk)
{
	pid_t pid;
	unsigned long ino;

	if (!key)
		return 0;

	pid = sock_cache_lookup(sk);
	if (pid > 0)
		return pid;

	if (sk) {
		ino = sock_i_ino((struct sock *)sk);
		pid = inode_cache_lookup(ino);
		if (pid > 0) {
			sock_cache_store(sk, pid);
			return pid;
		}
	}

	pid = flow_cache_lookup(key);
	if (pid > 0) {
		sock_cache_store(sk, pid);
		return pid;
	}

	resolver_schedule(key);
	return 0;
}

/**
 * tcp_state_from_header() - Derive analyzer state from TCP flags.
 * @tcp: TCP header.
 * @is_inbound: True for inbound hook.
 * @return: Connection state.
 * @note: Direction disambiguates SYN and SYN/ACK observations.
 */
static enum kta_conn_state tcp_state_from_header(const struct tcphdr *tcp,
						 bool is_inbound)
{
	if (tcp->rst)
		return KTA_STATE_CLOSED;
	if (tcp->fin)
		return KTA_STATE_FIN_WAIT;
	if (tcp->syn && tcp->ack)
		return KTA_STATE_SYN_RECEIVED;
	if (tcp->syn)
		return is_inbound ? KTA_STATE_SYN_RECEIVED : KTA_STATE_SYN_SENT;
	if (tcp->ack)
		return KTA_STATE_ESTABLISHED;
	return KTA_STATE_UNKNOWN;
}

/**
 * parse_transport() - Parse TCP/UDP headers and update statistics.
 * @skb: Packet buffer.
 * @offset: Transport header offset.
 * @key: Flow key with IP fields already populated.
 * @is_inbound: True for inbound hook.
 * @sk: Socket pointer from skb.
 * @pkt_len: Packet length to account.
 * @return: None.
 * @note: Malformed or unsupported transport packets are ignored.
 */
static void parse_transport(struct sk_buff *skb, unsigned int offset,
			    struct flow_key *key, bool is_inbound,
			    const struct sock *sk, u32 pkt_len)
{
	struct tcphdr tcp;
	struct udphdr udp;
	enum kta_conn_state state;
	pid_t pid;
	uid_t uid;
	char proc_name[MAX_PROC_NAME_LEN];

	if (key->protocol == IPPROTO_TCP) {
		if (skb_copy_bits(skb, offset, &tcp, sizeof(tcp)) != 0)
			return;
		key->src_port = tcp.source;
		key->dst_port = tcp.dest;
		state = tcp_state_from_header(&tcp, is_inbound);
	} else if (key->protocol == IPPROTO_UDP) {
		if (skb_copy_bits(skb, offset, &udp, sizeof(udp)) != 0)
			return;
		key->src_port = udp.source;
		key->dst_port = udp.dest;
		state = KTA_STATE_UDP;
	} else {
		return;
	}

	make_canonical(key);
	pid = resolve_pid_4tier(key, sk);
	parser_task_name(pid, proc_name, sizeof(proc_name));
	uid = parser_uid_from_sock(sk);
	stats_update(key, pid, uid, proc_name, pkt_len, is_inbound, state);
}

/**
 * parse_ipv4_packet() - Parse an IPv4 packet.
 * @skb: Packet buffer.
 * @is_inbound: True for inbound hook.
 * @return: None.
 * @note: Uses ip_hdr() after validating the version nibble.
 */
static void parse_ipv4_packet(struct sk_buff *skb, bool is_inbound)
{
	struct iphdr iph;
	struct flow_key key = { };
	unsigned int ihl;

	if (skb_copy_bits(skb, 0, &iph, sizeof(iph)) != 0)
		return;
	ihl = iph.ihl * 4U;
	if (ihl < sizeof(iph) || ihl > skb->len)
		return;
	key.src_ip = iph.saddr;
	key.dst_ip = iph.daddr;
	key.protocol = iph.protocol;
	parse_transport(skb, ihl, &key, is_inbound, skb->sk, skb->len);
}

/**
 * ipv6_ext_len() - Calculate the byte length of an IPv6 extension header.
 * @skb: Packet buffer.
 * @offset: Extension header offset.
 * @nexthdr: Extension header type.
 * @next: Destination for the following next-header value.
 * @return: Header length in bytes, or zero on malformed input.
 * @note: Fragment headers are fixed length; AUTH uses its own length formula.
 */
static unsigned int ipv6_ext_len(struct sk_buff *skb, unsigned int offset,
				 u8 nexthdr, u8 *next)
{
	struct ipv6_opt_hdr opt;

	if (skb_copy_bits(skb, offset, &opt, sizeof(opt)) != 0)
		return 0;
	*next = opt.nexthdr;
	if (nexthdr == NEXTHDR_FRAGMENT)
		return IPV6_EXT_MIN_LEN;
	if (nexthdr == NEXTHDR_AUTH)
		return (opt.hdrlen + IPV6_AUTH_HDR_BIAS) * IPV6_AUTH_HDR_UNIT;
	return (opt.hdrlen + 1U) * IPV6_EXT_MIN_LEN;
}

/**
 * parse_ipv6_packet() - Parse an IPv6 packet and extension headers.
 * @skb: Packet buffer.
 * @is_inbound: True for inbound hook.
 * @return: None.
 * @note: IPv6 addresses are represented by their last 32 bits in flow keys.
 */
static void parse_ipv6_packet(struct sk_buff *skb, bool is_inbound)
{
	struct ipv6hdr ip6h;
	struct flow_key key = { };
	unsigned int offset = IPV6_BASE_HDR_LEN;
	u8 nexthdr;

	if (skb_copy_bits(skb, 0, &ip6h, sizeof(ip6h)) != 0)
		return;

	key.src_ip = ip6h.saddr.s6_addr32[IPV6_ADDR_LAST_WORD];
	key.dst_ip = ip6h.daddr.s6_addr32[IPV6_ADDR_LAST_WORD];
	nexthdr = ip6h.nexthdr;

	while (nexthdr == NEXTHDR_HOP || nexthdr == NEXTHDR_ROUTING ||
	       nexthdr == NEXTHDR_DEST || nexthdr == NEXTHDR_FRAGMENT ||
	       nexthdr == NEXTHDR_AUTH) {
		unsigned int len;
		u8 next = NEXTHDR_NONE;

		if (offset + IPV6_EXT_MIN_LEN > skb->len)
			return;
		len = ipv6_ext_len(skb, offset, nexthdr, &next);
		if (!len || offset + len > skb->len)
			return;
		offset += len;
		nexthdr = next;
	}

	key.protocol = nexthdr;
	parse_transport(skb, offset, &key, is_inbound, skb->sk, skb->len);
}

/**
 * parse_packet() - Parse one packet observed by a Netfilter hook.
 * @skb: Packet buffer.
 * @is_inbound: True for LOCAL_IN hooks, false for LOCAL_OUT hooks.
 * @return: None.
 * @note: The version nibble is read from skb data rather than skb->protocol.
 */
void parse_packet(struct sk_buff *skb, bool is_inbound)
{
	u8 version_byte;

	if (!skb || skb->len < sizeof(version_byte))
		return;
	if (skb_copy_bits(skb, 0, &version_byte, sizeof(version_byte)) != 0)
		return;

	switch (version_byte >> 4) {
	case 4:
		parse_ipv4_packet(skb, is_inbound);
		break;
	case 6:
		parse_ipv6_packet(skb, is_inbound);
		break;
	default:
		break;
	}
}
