# Compiler settings
CC = clang
BPFTOOL = bpftool
GO = go

# Path to vmlinux.h
VMLINUX := /home/kali/Proj2/src/third_party/vmlinux/vmlinux.h

# Files
BPF_PROG = xdp_router.bpf.o
# USER_PROG = xdp_router_user
BPF_SKEL = xdp_router.skel.h
GO_PROG = xdp_router.go

# Compiler flags
CFLAGS = -g -O2 -Wall -Werror
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/home/kali/Proj2/src/third_party/vmlinux

# Linker flags
LDFLAGS = -lelf -lz -lbpf

# Default target
all: $(GO_PROG)

# Build BPF program
$(BPF_PROG): xdp_router.bpf.c
	$(CC) $(BPF_CFLAGS) -c $< -o $@

# Generate skeleton header
$(BPF_SKEL): $(BPF_PROG)
	$(BPFTOOL) gen skeleton $< > $@

$(GO_PROG): $(BPF_PROG)
	$(GO) build -o $(GO_PROG) xdp_router_userspace.go


# Clean up generated files
clean:
	rm -f $(BPF_PROG) $(GO_PROG) $(BPF_SKEL)

# Phony targets
.PHONY: all clean
