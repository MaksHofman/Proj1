#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "ipcapture.skel.h"  // Generated skeleton header

// Struktura, która odpowiada danym zapisanym w ring buffer
struct ip_info {
    __be32 src_ip;
    __be32 dest_ip;
};

// Callback funkcja do obsługi danych z ring buffer
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    if (data_sz != sizeof(struct ip_info)) {
        fprintf(stderr, "Received invalid data size: %zu\n", data_sz);
        return 0;
    }

    struct ip_info *info = (struct ip_info *)data;

    // Konwersja z sieciowego formatu na format hosta
    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &info->src_ip, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &info->dest_ip, dest_ip, INET_ADDRSTRLEN);

    printf("Captured IP Header:\n");
    printf("  Source IP: %s\n", src_ip);
    printf("  Destination IP: %s\n", dest_ip);
    printf("\n");

    return 0;
}

int main(int argc, char **argv)
{
    struct ipcapture_bpf *skel;
    struct ring_buffer *rb = NULL;
    int ifindex;
    int err;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
    {
        fprintf(stderr, "Invalid interface name %s\n", ifname);
        return 1;
    }

    /* Open and load BPF application */
    skel = ipcapture_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = ipcapture_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Attach XDP program */
    err = ipcapture_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Attach the XDP program to the specified interface */
    skel->links.xdp_pass = bpf_program__attach_xdp(skel->progs.xdp_pass, ifindex);
    if (!skel->links.xdp_pass)
    {
        err = -errno;
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Successfully attached XDP program to interface %s\n", ifname);

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb)
    {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("Start polling ring buffer\n");

    /* Poll the ring buffer */
    while (1)
    {
        err = ring_buffer__poll(rb, -1);
        if (err == -EINTR)
            continue;
        if (err < 0)
        {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    cleanup:
    ring_buffer__free(rb);
    ipcapture_bpf__destroy(skel);
    return -err;
}
