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
    int out_ifindex;             // Indeks interfejsu wyjściowego
    __be32 next_hop_ip;          // Adres IP następnego przeskoku
    __u8 dst_mac[ETH_ALEN];      // Docelowy adres MAC
    __u8 src_mac[ETH_ALEN];      // Źródłowy adres MAC
};

// Mapa routingu (BPF_MAP_TYPE_LPM_TRIE)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __uint(key_size, sizeof(struct lpm_trie_key));
    __uint(value_size, sizeof(struct route_entry));
    __uint(map_flags, BPF_F_NO_PREALLOC);
} routing_table SEC(".maps");

// Mapa ARP (BPF_MAP_TYPE_HASH)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __be32);
    __type(value, __u8[ETH_ALEN]);
} arp_table SEC(".maps");

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

    // Debugowanie: Printujemy adres IP docelowy i interfejs wejściowy
    bpf_printk("Packet received: src_ifindex=%d, dst IP=%x\n", 
                ctx->ingress_ifindex, bpf_ntohl(ip->daddr));

    // Tworzenie klucza LPM
    struct lpm_trie_key key = {
        .prefixlen = 32,
        .ip = ip->daddr,
    };

    // Wyszukiwanie wpisu w tablicy routingu
    struct route_entry *route = bpf_map_lookup_elem(&routing_table, &key);
    if (!route) {
        bpf_printk("No route found for dst IP: %x, dropping packet\n", bpf_ntohl(ip->daddr));
        return XDP_DROP;
    }

    // Jeśli next_hop_ip jest równy dst_ip, przechodzimy do jądra
    if (route->next_hop_ip == ip->daddr) {
          bpf_printk("Next hop IP = %x is the same as dst IP, passing packet to kernel\n", bpf_ntohl(route->next_hop_ip));
         return XDP_PASS;
    }

    // Sprawdzenie tabeli ARP dla next_hop_ip
    __u8 *dest_mac = bpf_map_lookup_elem(&arp_table, &route->next_hop_ip);
    if (!dest_mac) {
        bpf_printk("No ARP entry for next_hop_ip: %x, \n", bpf_ntohl(route->next_hop_ip));
        return XDP_DROP;
    }

    // Ustawienie adresów MAC
    __builtin_memcpy(eth->h_dest, dest_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, route->src_mac, ETH_ALEN);

    // Przekierowanie pakietu na odpowiedni interfejs
    int ret = bpf_redirect(route->out_ifindex, 0);
    if (ret == XDP_REDIRECT) {
        bpf_printk("Packet redirected to ifindex = %d, next_hop_ip = %x, next_hop_mac = %02x:%02x:%02x:%02x:%02x:%02x\n",
              route->out_ifindex, bpf_ntohl(route->next_hop_ip), dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);
    }
    return ret;
}

char _license[] SEC("license") = "GPL";