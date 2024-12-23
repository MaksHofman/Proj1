#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

// Zdefiniowanie ring buffer map, aby tam przechowywać dane o pakietach
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // bufor 16 MB
} rb SEC(".maps");

// Zdefiniowanie zmiennych do przechowywania informacji o source ip i destination ip
struct ip_info {
    __be32 src_ip;
    __be32 dest_ip;
};

// Sprawdzenie czy pakiet jest IPv4
static bool is_ipv4(struct ethhdr *eth, void *data_end)
{
    // Sprawdzenie czy nagłówek Ethernet jest w granicach danych pakietu (żeby nie wystąpiły błędy pamięciowe)
    if ((void *)(eth + 1) > data_end)
        return false;

    // Warunek który obługuje tylko pakiety IPv4
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return false;

    return true;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    // Pointery do początkowych danych pakietu i końcowych
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Identyfikacja nagłówka ethernet
    struct ethhdr *eth = data;

    // Sprawdzenie czy pakiet jest IPv4
    if (!is_ipv4(eth, data_end)) {
        return XDP_PASS;
    }

    // Przekształcenie pointera na nagłówek IP
    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // Sprawdzenie czy nagłówek IP jest w granicach danych pakietu (żeby nie wystąpiły błędy pamięciowe)
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // Uzyskanie infomracji o source ip i destination ip
    struct ip_info info = {
        .src_ip = ip->saddr,
        .dest_ip = ip->daddr
    };

    // Zarezerwowanie miejsca w ring buffer map do zapisu danych o nagłówku IP
    void *ringbuf_space = bpf_ringbuf_reserve(&rb, sizeof(info), 0);
    if (!ringbuf_space) {
        return XDP_PASS;
    }

    // Skopiowanie danych o nagłówku IP do mapy
    *(struct ip_info *)ringbuf_space = info;

    // Wysłanie danych o nagłówku IP do mapy
    bpf_ringbuf_submit(ringbuf_space, 0);

    // Wypisanie informacji o source ip i destination ip
    bpf_printk("Captured src_ip: %x, dest_ip: %x", bpf_ntohl(info.src_ip), bpf_ntohl(info.dest_ip));

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
