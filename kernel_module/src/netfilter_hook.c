/**
 * @file netfilter_hook.c
 * @brief Netfilter hook registration and packet dispatch.
 * @details Four LOCAL_IN/LOCAL_OUT hooks cover IPv4 and IPv6 traffic. Inbound
 * UDP DNS responses are parsed before general packet accounting so DNS answers
 * can be associated with the same packet's traffic update.
 * @author Kernel Traffic Analyzer Project
 * @license GPL-2.0
 */

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <net/net_namespace.h>
#include "../include/kta_api.h"

static struct nf_hook_ops kta_nf_ops[4];
static unsigned int registered_hooks;

/**
 * maybe_parse_dns_v4() - Parse inbound IPv4 DNS responses before stats.
 * @skb: Packet buffer.
 * @return: None.
 * @note: Only UDP packets with source port DNS_PORT are parsed.
 */
static void maybe_parse_dns_v4(struct sk_buff *skb)
{
	struct iphdr iph;
	struct udphdr udp;
	unsigned int ihl;

	if (!skb || skb_copy_bits(skb, 0, &iph, sizeof(iph)) != 0)
		return;
	ihl = iph.ihl * 4U;
	if (iph.protocol != IPPROTO_UDP || ihl + sizeof(udp) > skb->len)
		return;
	if (skb_copy_bits(skb, ihl, &udp, sizeof(udp)) != 0)
		return;
	if (ntohs(udp.source) == DNS_PORT)
		dns_parse_response(skb, ihl + sizeof(udp));
}

/**
 * maybe_parse_dns_v6() - Parse inbound IPv6 DNS responses before stats.
 * @skb: Packet buffer.
 * @return: None.
 * @note: This handles non-extension-header UDP DNS responses.
 */
static void maybe_parse_dns_v6(struct sk_buff *skb)
{
	struct ipv6hdr ip6h;
	struct udphdr udp;

	if (!skb || skb_copy_bits(skb, 0, &ip6h, sizeof(ip6h)) != 0)
		return;
	if (ip6h.nexthdr != IPPROTO_UDP ||
	    IPV6_BASE_HDR_LEN + sizeof(udp) > skb->len)
		return;
	if (skb_copy_bits(skb, IPV6_BASE_HDR_LEN, &udp, sizeof(udp)) != 0)
		return;
	if (ntohs(udp.source) == DNS_PORT)
		dns_parse_response(skb, IPV6_BASE_HDR_LEN + sizeof(udp));
}

/**
 * hook_ipv4_in() - IPv4 inbound Netfilter callback.
 * @priv: Hook private data.
 * @skb: Packet buffer.
 * @state: Netfilter hook state.
 * @return: NF_ACCEPT always.
 * @note: DNS parsing runs before generic packet parsing.
 */
static unsigned int hook_ipv4_in(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	maybe_parse_dns_v4(skb);
	parse_packet(skb, true);
	return NF_ACCEPT;
}

/**
 * hook_ipv4_out() - IPv4 outbound Netfilter callback.
 * @priv: Hook private data.
 * @skb: Packet buffer.
 * @state: Netfilter hook state.
 * @return: NF_ACCEPT always.
 * @note: Outbound DNS requests are accounted but not parsed into the DNS map.
 */
static unsigned int hook_ipv4_out(void *priv, struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	parse_packet(skb, false);
	return NF_ACCEPT;
}

/**
 * hook_ipv6_in() - IPv6 inbound Netfilter callback.
 * @priv: Hook private data.
 * @skb: Packet buffer.
 * @state: Netfilter hook state.
 * @return: NF_ACCEPT always.
 * @note: DNS response parsing is attempted before traffic accounting.
 */
static unsigned int hook_ipv6_in(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	maybe_parse_dns_v6(skb);
	parse_packet(skb, true);
	return NF_ACCEPT;
}

/**
 * hook_ipv6_out() - IPv6 outbound Netfilter callback.
 * @priv: Hook private data.
 * @skb: Packet buffer.
 * @state: Netfilter hook state.
 * @return: NF_ACCEPT always.
 * @note: All outbound IPv6 packets are accepted after accounting.
 */
static unsigned int hook_ipv6_out(void *priv, struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	parse_packet(skb, false);
	return NF_ACCEPT;
}

/**
 * nf_hook_init() - Register all Kernel Traffic Analyzer Netfilter hooks.
 * @return: Zero on success or a negative errno from Netfilter registration.
 * @note: Any partial registration is unwound before returning an error.
 */
int nf_hook_init(void)
{
	int ret;
	unsigned int idx;

	kta_nf_ops[0].hook = hook_ipv4_in;
	kta_nf_ops[0].pf = PF_INET;
	kta_nf_ops[0].hooknum = NF_INET_LOCAL_IN;
	kta_nf_ops[0].priority = NF_IP_PRI_FIRST;
	kta_nf_ops[1].hook = hook_ipv4_out;
	kta_nf_ops[1].pf = PF_INET;
	kta_nf_ops[1].hooknum = NF_INET_LOCAL_OUT;
	kta_nf_ops[1].priority = NF_IP_PRI_FIRST;
	kta_nf_ops[2].hook = hook_ipv6_in;
	kta_nf_ops[2].pf = PF_INET6;
	kta_nf_ops[2].hooknum = NF_INET_LOCAL_IN;
	kta_nf_ops[2].priority = NF_IP_PRI_FIRST;
	kta_nf_ops[3].hook = hook_ipv6_out;
	kta_nf_ops[3].pf = PF_INET6;
	kta_nf_ops[3].hooknum = NF_INET_LOCAL_OUT;
	kta_nf_ops[3].priority = NF_IP_PRI_FIRST;

	registered_hooks = 0;
	for (idx = 0; idx < ARRAY_SIZE(kta_nf_ops); idx++) {
		ret = nf_register_net_hook(&init_net, &kta_nf_ops[idx]);
		if (ret) {
			pr_err("kta: netfilter_hook: hook registration failed: %d\n",
			       ret);
			while (registered_hooks)
				nf_unregister_net_hook(&init_net,
						       &kta_nf_ops[--registered_hooks]);
			return ret;
		}
		registered_hooks++;
	}

	return 0;
}

/**
 * nf_hook_exit() - Unregister all registered Netfilter hooks.
 * @return: None.
 * @note: Safe when initialization partially failed.
 */
void nf_hook_exit(void)
{
	while (registered_hooks)
		nf_unregister_net_hook(&init_net,
				       &kta_nf_ops[--registered_hooks]);
}

