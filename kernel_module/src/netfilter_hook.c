#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>

#include "../include/traffic_analyzer.h"

static struct nf_hook_ops nfho;

static unsigned int packet_hook(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    if (!skb)
        return NF_ACCEPT;

    parse_packet(skb);

    return NF_ACCEPT;
}

int netfilter_hook_init(void)
{
    int ret;

    nfho.hook = packet_hook;
    nfho.hooknum = NF_INET_LOCAL_OUT;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    ret = nf_register_net_hook(&init_net, &nfho);
    if (ret)
    {
        printk(KERN_ERR "[traffic_analyzer] netfilter hook registration failed\n");
        return ret;
    }

    printk(KERN_INFO "[traffic_analyzer] netfilter hook registered\n");

    return 0;
}

void netfilter_hook_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);

    printk(KERN_INFO "[traffic_analyzer] netfilter hook removed\n");
}