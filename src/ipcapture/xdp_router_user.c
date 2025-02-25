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

void display_routing_table(int map_fd)
{
    struct lpm_key key, next_key;
    struct route_entry entry;

    printf("\nRouting Table:\n");
    printf("%-15s %-5s %-17s\n", "Destination", "Prefix", "Next Hop MAC");

    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &entry) == 0) {
            struct in_addr ip_addr = { .s_addr = next_key.ip };
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str));

            printf("%-15s %-5u %02x:%02x:%02x:%02x:%02x:%02x\n",
                   ip_str,
                   next_key.prefixlen,
                   entry.next_hop_mac[0], entry.next_hop_mac[1], entry.next_hop_mac[2],
                   entry.next_hop_mac[3], entry.next_hop_mac[4], entry.next_hop_mac[5]);
        }
        key = next_key;
    }
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


    printf("Router is running on interface %s\n", ifname);
    printf("Press Ctrl+C to stop.\n");

    // Display the routing table every 10 seconds
    int map_fd = bpf_map__fd(skel->maps.routing_table);
    if (map_fd < 0) {
        fprintf(stderr, "Error getting routing table map FD\n");
        return 1;
    }

    while (1) {
        display_routing_table(map_fd);
        sleep(10);
    }

    // Clean up
    xdp_router_bpf__destroy(skel);
    return 0;
}
