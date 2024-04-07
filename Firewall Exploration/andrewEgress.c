#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>

static struct nf_hook_ops nfho;

// IP addresses to be filtered
unsigned int blocked_ip1 = 0x0402a8c0; // 10.0.2.4
unsigned int blocked_ip2 = 0x0502a8c0; // 10.0.2.5
unsigned int target_ip1 = 0x3b1930ac;  // walmart.com (59.25.49.59)
unsigned int target_ip2 = 0xd431c0ac;  // target.com (205.49.96.212)
unsigned int telnet_server1 = 0x0a01a8c0;  // External telnet server 1 (192.168.1.10)
unsigned int telnet_server2 = 0x0a02a8c0;  // External telnet server 2 (192.168.2.10)
unsigned int facebook_ip1 = 0x2311431f;  // Facebook IP address 1 (31.13.67.35)
unsigned int facebook_ip2 = 0x23f0e595;  // Facebook IP address 2 (157.240.229.35)
unsigned int facebook_ip3 = 0x23f1f135;  // Facebook IP address 3 (157.240.241.35)

static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    if (!skb)
        return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph)
        return NF_ACCEPT;

    // Block telnet from 10.0.2.4 to 10.0.2.5
    if (iph->saddr == blocked_ip1 && iph->daddr == blocked_ip2 && iph->protocol == IPPROTO_TCP)
        return NF_DROP;

    // Block telnet from 10.0.2.5 to 10.0.2.4
    if (iph->saddr == blocked_ip2 && iph->daddr == blocked_ip1 && iph->protocol == IPPROTO_TCP)
        return NF_DROP;

    // Block access to walmart.com from 10.0.2.4
    if (iph->saddr == blocked_ip1 && ntohl(iph->daddr) == target_ip1 && iph->protocol == IPPROTO_TCP)
        return NF_DROP;

    // Block access to target.com from 10.0.2.5
    if (iph->saddr == blocked_ip2 && ntohl(iph->daddr) == target_ip2 && iph->protocol == IPPROTO_TCP)
        return NF_DROP;

    // Block outgoing traffic to external telnet servers
    if ((iph->saddr == blocked_ip1 || iph->saddr == blocked_ip2) &&
        (iph->daddr == telnet_server1 || iph->daddr == telnet_server2) &&
        iph->protocol == IPPROTO_TCP)
        return NF_DROP;

    // Block outgoing traffic to Facebook.com
    if ((iph->saddr == blocked_ip1 || iph->saddr == blocked_ip2) &&
        (ntohl(iph->daddr) == facebook_ip1 || ntohl(iph->daddr) == facebook_ip2 || ntohl(iph->daddr) == facebook_ip3) &&
        iph->protocol == IPPROTO_TCP)
        return NF_DROP;

    // Allow SSH from 10.0.2.4 to 10.0.2.5
    if (iph->saddr == blocked_ip1 && iph->daddr == blocked_ip2 && iph->protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);
        if (ntohs(tcph->dest) == 22)
            return NF_ACCEPT;
    }

    return NF_ACCEPT;
}

static int __init init_func(void)
{
    nfho.hook = hook_func;
    nfho.pf = PF_INET;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_hook(&nfho);

    return 0;
}

static void __exit exit_func(void)
{
    nf_unregister_hook(&nfho);
}

module_init(init_func);
module_exit(exit_func);

MODULE_LICENSE("GPL");
