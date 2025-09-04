FROM rust:1-slim-bookworm

RUN apt-get update && \
    apt-get install -y \
    libcap2 \
    iproute2 \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/rust-dhcp

CMD ["/bin/bash"]

# cd /Users/lrehak/rustprojects/rust-dhcp
# docker build -t rust-dhcp-dev .
# docker run --network host -it --rm -v /Users/lrehak/rustprojects/rust-dhcp:/usr/src/rust-dhcp rust-dhcp-dev /bin/bash
