# Compiler & Tool Settings
CC = clang
BPFTOOL = bpftool
GO = go

# Paths
VMLINUX := /home/kali/Proj2/src/third_party/vmlinux/vmlinux.h
INCLUDES := -I$(dir $(VMLINUX))

# Files
BPF_SRC = xdp_router.bpf.c
BPF_OBJ = xdp_router.bpf.o
# USER_PROG = xdp_router_user
BPF_SKEL = xdp_router.skel.h
GO_SRC = xdp_router_userspace.go
GO_SRC += hello.go
GO_OUT = xdp_router

# Flags
CFLAGS = -g -O2 -Wall -Werror
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 $(INCLUDES)

# Targets

.PHONY: all clean

all: $(GO_OUT)

# Compile eBPF program

$(BPF_OBJ): $(BPF_SRC)
	$(CC) $(BPF_CFLAGS) -c $< -o $@

# Generate skeleton header (used with libbpf)
$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Build Go userspace app
$(GO_OUT): $(GO_SRC) $(BPF_OBJ) $(BPF_SKEL)
	$(GO) build -o $@ $(GO_SRC)

clean:
	rm -f $(BPF_OBJ) $(BPF_SKEL) $(GO_OUT)
