# Compiler settings
CC = clang
BPFTOOL = bpftool

# Path to vmlinux.h
VMLINUX := /workspaces/Proj1/src/third_party/vmlinux/vmlinux.h

# Files
BPF_PROG = xdp_router.bpf.o
USER_PROG = xdp_router_user
BPF_SKEL = xdp_router.skel.h

# Compiler flags
CFLAGS = -g -O2 -Wall -Werror
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/workspaces/Proj1/src/third_party/vmlinux

# Linker flags
LDFLAGS = -lelf -lz -lbpf

# Default target
all: $(USER_PROG)

# Build BPF program
$(BPF_PROG): xdp_router.bpf.c
	$(CC) $(BPF_CFLAGS) -c $< -o $@

# Generate skeleton header
$(BPF_SKEL): $(BPF_PROG)
	$(BPFTOOL) gen skeleton $< > $@

# Build user-space program
$(USER_PROG): xdp_router_user.c $(BPF_SKEL)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Clean up generated files
clean:
	rm -f $(BPF_PROG) $(USER_PROG) $(BPF_SKEL)

# Phony targets
.PHONY: all clean

