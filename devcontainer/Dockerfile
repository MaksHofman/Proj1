FROM mcr.microsoft.com/devcontainers/go:1.23-bookworm

RUN apt-get update && \
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y tshark && \
    apt-get install -y \
        build-essential \
        pkg-config \
        clang \
        llvm \
        m4 \
        git \
        libelf-dev \
        libpcap-dev \
        iproute2 \
        iputils-ping \
        linux-headers-amd64 \
        libbpf-dev \
        linux-libc-dev \
        cmake \
        libcap-ng-dev \
        libbfd-dev \
        libcap-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN ln -sf /usr/local/go/bin/go /bin/go
RUN [ -d /usr/include/asm ] || ln -sf /usr/include/asm-generic /usr/include/asm

WORKDIR /sources

RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git && \
    make -C bpftool/src/ install && \
    git clone --recurse-submodules https://github.com/xdp-project/xdp-tools.git && \
    make -C xdp-tools/ install
