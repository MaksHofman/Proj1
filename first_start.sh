docker build -t ebpf-proj-devcontainer -f devcontainer/Dockerfile .
docker run -it --rm --name ebpf-proj-devcontainer --privileged -v "$(pwd)/src:/sources" ebpf-proj-devcontainer bash
#klinac lewy dolny(remote access) i wybrac attach to running container i kliknac ebpf_container