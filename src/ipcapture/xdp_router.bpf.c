/* BPF Program */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define ETH_ALEN 6

// Mapa routingu z BPF_MAP_TYPE_LPM_TRIE
struct lpm_key {
    __u32 prefixlen; // Długość prefiksu
    __be32 ip;       // Adres IP
};

struct route_entry {
    int out_ifindex;               // Indeks interfejsu wyjściowego
    __u8 next_hop_mac[ETH_ALEN];  // Adres MAC następnego przeskoku
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __uint(key_size, sizeof(struct lpm_key));
    __uint(value_size, sizeof(struct route_entry));
    __uint(map_flags, BPF_F_NO_PREALLOC);
} routing_table SEC(".maps");

// Sprawdzenie czy pakiet jest IPv4
static bool is_ipv4(struct ethhdr *eth, void *data_end)
{
    if ((void *)(eth + 1) > data_end)
        return false;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return false;
    return true;
}

SEC("xdp")
int xdp_router(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    if (!is_ipv4(eth, data_end)) {
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    struct lpm_key key = {
        .prefixlen = 32,
        .ip = ip->daddr
    };

    struct route_entry *route = bpf_map_lookup_elem(&routing_table, &key);
    if (!route) {
        bpf_printk("No route found for IP: %x\n", bpf_ntohl(ip->daddr));
        return XDP_DROP;
    }

    __builtin_memcpy(eth->h_dest, route->next_hop_mac, ETH_ALEN);
    return bpf_redirect(route->out_ifindex, 0);
}

char __license[] SEC("license") = "GPL";
