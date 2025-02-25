#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define ETH_ALEN 6

// Klucz LPM Trie
struct lpm_trie_key {
    __u32 prefixlen; // Długość prefiksu
    __be32 ip;       // Adres IP
};

// Wpis w tablicy routingu
struct route_entry {
    int out_ifindex;               // Indeks interfejsu wyjściowego
    __u8 next_hop_mac[ETH_ALEN];   // Adres MAC następnego przeskoku
};

// Mapa routingu (BPF_MAP_TYPE_LPM_TRIE)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __uint(key_size, sizeof(struct lpm_trie_key));
    __uint(value_size, sizeof(struct route_entry));
    __uint(map_flags, BPF_F_NO_PREALLOC);
} routing_table SEC(".maps");

// XDP Program
SEC("xdp")
int xdp_router(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;

    // Sprawdzenie, czy to jest pakiet IPv4
    if ((void *)(eth + 1) > data_end || bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // Tworzenie klucza LPM
    struct lpm_trie_key key = {
        .prefixlen = 32,
        .ip = ip->daddr,
    };

    // Wyszukiwanie wpisu w tablicy routingu
    bpf_printk("Processing packet: daddr=%x\n", bpf_ntohl(ip->daddr));
    bpf_printk("Looking up key: prefixlen=%d, ip=%x\n", key.prefixlen, bpf_ntohl(key.ip));
    bpf_printk("Processing ICMP reply: daddr=%x, saddr=%x\n", bpf_ntohl(ip->daddr), bpf_ntohl(ip->saddr));
    struct route_entry *route = bpf_map_lookup_elem(&routing_table, &key);

    if (!route) {
        // Brak trasy dla adresu, upuszczenie pakietu
        bpf_printk("No route for daddr: %x\n", bpf_ntohl(ip->daddr));
        return XDP_DROP;
    }

    // Modyfikacja adresu MAC na docelowy i przekierowanie pakietu
    __builtin_memcpy(eth->h_dest, route->next_hop_mac, ETH_ALEN);
    bpf_printk("Modified dest MAC to: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    bpf_printk("Destination IP (daddr): %x\n", bpf_ntohl(ip->daddr));
    bpf_printk("Lookup Key: prefixlen=%d, ip=%x\n", key.prefixlen, bpf_ntohl(key.ip));
    bpf_printk("Packet forwarded to ifindex: %d\n", route->out_ifindex);
    return bpf_redirect(route->out_ifindex, 0);
}

char __license[] SEC("license") = "GPL";
