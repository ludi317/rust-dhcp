# Manual test runbook — DHCPv6 against Kea

> **See also:** [`../lab/README.md`](../lab/README.md) — scripted end-to-end
> version of these checks (veth+Kea in Docker, works on macOS).

Phase 1 (MIST-202976) ships without automated CI for DHCPv6. This runbook is
the supported way to verify the `--ipv6` path end-to-end. Run on Linux —
netlink address ops require a Linux kernel.

## Prerequisites

- Kea DHCPv6 (`apt install kea-dhcp6-server` on Debian/Ubuntu, `brew install kea`
  on macOS hosts that ship Kea but cannot run the client side of this test).
- Root or `CAP_NET_ADMIN` + `CAP_NET_RAW` for the rust-dhcp client.
- A `target/debug/client` or `target/release/client` build:
  ```
  cargo build --bin client
  ```

## One-shot setup — veth pair in a netns

```bash
sudo ip netns add v6test
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns v6test
sudo ip link set veth0 up
sudo ip -6 addr add 2001:db8:1::1/64 dev veth0
sudo ip netns exec v6test ip link set veth1 up
sudo ip netns exec v6test ip link set lo up
sudo mkdir -p /etc/netns/v6test
```

## Run Kea on the host side

```bash
sudo kea-dhcp6 -c tests/fixtures/kea-dhcp6.conf
```

Leave it running in a foreground terminal — its log is the easiest place to
watch for SOLICIT/ADVERTISE/REQUEST/REPLY/RENEW traffic.

## Run rust-dhcp inside the netns

```bash
sudo ip netns exec v6test \
    ./target/debug/client \
        --ipv6 \
        --resolv-conf-path /etc/netns/v6test/resolv.conf \
        --duid-path /tmp/duid-veth1 \
        --solicit-timeout 30 \
        veth1
```

## What to verify

1. **Lease applied** — `sudo ip netns exec v6test ip -6 addr show veth1 scope global`
   shows an address from the `2001:db8:1::100/64` pool.
2. **DNS written** — `cat /etc/netns/v6test/resolv.conf.ipv6` shows the two
   `2001:db8::53/54` nameservers plus `search example.test lab.example.test`.
3. **Renewal at T1** — wait ~20 s; the rust-dhcp log emits a second
   `✅ DHCPv6 lease received` (there is no explicit `→ Renew` line — renewal
   is inferred from the recurring lease-received message and the matching
   `RENEW`/`REPLY` pair in Kea's log).
4. **Rebind on server loss** — kill Kea after a successful lease. `renew_phase`
   retries internally until the 60s valid lifetime elapses, so the
   `T2 reached during renewal; switching to REBIND` log line appears roughly
   at lease expiry (~60s after bind), not at T2 (40s). Then the client exits
   the lifecycle with `LeaseExpired` and re-solicits.
5. **Clean release on SIGTERM** — `sudo kill -TERM <pid>`. Log shows
   `📤 DHCPv6 RELEASE`, the leased address is removed from `veth1`, and
   `resolv.conf.ipv6` is restored.
6. **Manual renew** — `sudo kill -HUP <pid>` or `kill -USR1 <pid>` while
   bound. Log shows `🔄 SIGHUP received - initiating DHCPv6 lease renewal`.
7. **Negative path** — stop Kea, restart rust-dhcp. After `--solicit-timeout`
   (30s default) the client exits non-zero with `SOLICIT timed out`. Matches
   `udhcpc6 -n` semantics.

## DUID persistence

The DUID-LLT is written to `--duid-path` on first run and reused on
subsequent invocations. Confirm: `xxd /tmp/duid-veth1` shows 14 bytes, first
two bytes `0001` (DUID-LLT type), next two `0001` (Ethernet hardware type).
Re-running the client should produce the same DUID — Kea will recognize the
returning client and re-issue the previous address if still available.

## IPv4 regression

After exercising `--ipv6`, run the binary without flags against a DHCPv4
server to confirm IPv4 behavior is unchanged:

```bash
sudo ./target/debug/client veth1
```

The `<resolv-conf-path>.ipv4` file should be written (default
`/etc/resolv.conf.ipv4`) and v4 DORA should complete.

## Tearing down

```bash
sudo ip netns del v6test
sudo ip link del veth0   # peer is auto-removed
```
