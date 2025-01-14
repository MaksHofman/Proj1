#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp_router.skel.h"

#define ETH_ALEN 6

// Include missing struct definitions
struct lpm_key {
    __u32 prefixlen;
    __be32 ip;
};

struct route_entry {
    int out_ifindex;
    __u8 next_hop_mac[ETH_ALEN];
};

struct xdp_router_bpf *skel; // Skeleton object

int add_route_entry(__u32 prefixlen, __be32 ip, int out_ifindex, unsigned char *next_hop_mac)
{
    struct lpm_key key = {
        .prefixlen = prefixlen,
        .ip = ip,
    };

    struct route_entry entry = {
        .out_ifindex = out_ifindex,
    };

    memcpy(entry.next_hop_mac, next_hop_mac, ETH_ALEN);

    int map_fd = bpf_map__fd(skel->maps.routing_table);
    if (map_fd < 0) {
        fprintf(stderr, "Error getting routing table map FD\n");
        return -1;
    }

    if (bpf_map_update_elem(map_fd, &key, &entry, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to add route entry\n");
        return -1;
    }

    printf("Added route: %x/%u -> ifindex %d\n",
           ntohl(ip), prefixlen, out_ifindex);
    return 0;
}

int main(int argc, char **argv)
{
    int err;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Invalid interface name %s\n", ifname);
        return 1;
    }

    // Open BPF skeleton
    skel = xdp_router_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Load and verify BPF skeleton
    err = xdp_router_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        return 1;
    }

    // Attach XDP program
    skel->links.xdp_router = bpf_program__attach_xdp(skel->progs.xdp_router, ifindex);
    if (!skel->links.xdp_router) {
        fprintf(stderr, "Failed to attach XDP program\n");
        return 1;
    }

    // Add example routing entry
    unsigned char mac[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x3e, 0x4b, 0x55};
    add_route_entry(24, htonl(0xC0A80100), ifindex, mac);

    printf("Router is running on interface %s\n", ifname);
    printf("Press Ctrl+C to stop.\n");

    // Keep the program running
    while (1) {
        sleep(1);
    }

    // Clean up
    xdp_router_bpf__destroy(skel);
    return 0;
}
