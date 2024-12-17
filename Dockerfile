# Use an Ubuntu base image
FROM ubuntu:22.04

# Set non-interactive mode for apt
ENV DEBIAN_FRONTEND=noninteractive

# Update the package list and install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    gcc \
    libelf-dev \
    libbpf-dev \
    make \
    iproute2 \
    iputils-ping \
    vim \
    git \
    curl \
    wget \
    python3 \
    python3-pip \
    build-essential \
    linux-headers-$(uname -r) \
    net-tools \
    software-properties-common \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz -O /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

# Add Go to PATH
ENV PATH="/usr/local/go/bin:$PATH"
ENV GOPATH="/go"
ENV PATH="$GOPATH/bin:$PATH"

# Set the working directory
WORKDIR /app

# Clone the LEEP repository
RUN git clone https://github.com/eBPFdev/leep.git /app/leep

# Install Python dependencies for LEEP
RUN pip3 install -r /app/leep/requirements.txt

# Build LEEP
RUN make -C /app/leep

# Optional: Install additional Go dependencies for eBPF development
RUN go install github.com/cilium/ebpf/cmd/bpf2go@latest \
    && go install github.com/cilium/ebpf/cmd/rls@latest

# Set the default working directory
WORKDIR /app/leep

# Expose a port if required (for example, if LEEP runs a server or web interface)
EXPOSE 8080

# Set the default entry point
ENTRYPOINT ["/app/leep/leep"]
