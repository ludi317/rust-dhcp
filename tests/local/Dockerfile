# Debian slim + Kea DHCPv6 + iproute2 + iputils-ping.
# Used by tests/local/local-kea-docker.sh to run the veth+Kea integration tests
# on macOS dev boxes without a full Linux VM.
FROM debian:12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        kea-dhcp6-server \
        iproute2 \
        iputils-ping \
        procps \
        xxd \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/run/kea /var/lib/kea

WORKDIR /repo
