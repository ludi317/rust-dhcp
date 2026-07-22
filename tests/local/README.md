# rust-dhcp lab integration tests

Scripted end-to-end tests for the DHCPv6 client added on `MIST-202976`. The
client runs inside a Linux network namespace against Kea DHCPv6 on the other
end of a veth pair; the whole thing runs in a Debian container on macOS, or
directly on a Linux host. Currently: **10/10 pass** in ~2m45s.

The same seven behaviors the manual runbook in
[`../manual/README.md`](../manual/README.md) walks through are asserted here,
plus a Kea server-side binding check and a DUID-stability check.

## Test matrix

| # | Name                            | What it asserts           |
| --| --------------------------------| --------------------------|
| 1 | Namespace has IPv6              | veth link-local present   |
| 2 | DHCPv6 lease acquired           | global v6 from Kea pool   |
| 3 | `resolv.conf.ipv6` written      | DNS servers + search dom  |
| 4 | Server sees the binding         | Kea lease file has entry  |
| 5 | Renew at T1                     | second lease-received log |
| 6 | Rebind on server loss           | kill Kea, wait for REBIND |
| 7 | Clean release on SIGTERM        | RELEASE + addr removed    |
| 8 | Manual renew via SIGHUP         | SIGHUP triggers renewal   |
| 9 | SOLICIT timeout when no server  | non-zero exit with reason |
| 10| DUID stability across restarts  | DUID file unchanged       |

## Running the tests

### On macOS (Docker container)

Requires the Rust toolchain with a matching Linux/musl target and any docker
CLI (Docker Desktop, OrbStack, colima, Rancher Desktop). Cross-linking uses
[`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) (macOS `cc`
does not accept GNU ld options).

```bash
# One-time
rustup target add aarch64-unknown-linux-musl   # Apple Silicon
# or
rustup target add x86_64-unknown-linux-musl    # Intel
brew install zig
cargo install cargo-zigbuild

# Run
tests/local/local-kea-docker.sh
```

The wrapper detects host arch, cross-compiles `client` for the matching
`*-unknown-linux-musl` target, builds `tests/local/Dockerfile` (Debian 12 slim +
`kea-dhcp6-server` + `iproute2`), and runs `local-kea.sh` inside the container
with a narrow capability set (`--cap-add=NET_ADMIN`, `NET_RAW`,
`NET_BIND_SERVICE`, `--network=none`).

Env overrides: `IMAGE_TAG`, `RUST_TARGET`, `PROFILE=debug|release`,
`SKIP_BUILD=1`, `ONLY=1,2,7` (subset of tests).

### On a Linux host

```bash
cargo build --bin client
sudo tests/local/local-kea.sh
```

Env overrides: `CLIENT_BIN`, `KEA_CONF`, `NS`, `HOST_IF`, `NS_IF`, `PREFIX`,
`ONLY`.

## SRX-served DHCPv6 (for `ep-control` follow-up work)

The SRX300 in the lab is configured for stateful DHCPv6 + RA on
`irb.{1,3,5,7,9}` — see [`srx-config-v6-all.set`](srx-config-v6-all.set). This
is not exercised by the automated suite here (the AP37 firmware image lacks
`CONFIG_VLAN_8021Q`, so a scripted client cannot bring up an arbitrary
`vlanN` sub-interface from userspace); the config is provisioned so the
`ep-control` DHCPv6 integration can point at any of those IRBs without
further SRX work.

**Verify the SRX config is live:**

```bash
ssh srx300 "cli -c 'show interfaces terse irb'"          # inet6 on 1/3/5/7/9
ssh srx300 "cli -c 'show ipv6 router-advertisement'"     # RAs sent per irb
ssh srx300 "cli -c 'show dhcpv6 server statistics'"      # zero until first SOLICIT
```

**Re-apply from scratch** (e.g. after a `rollback`):

```bash
scp -O tests/local/srx-config-v6-all.set srx300:/var/tmp/v6-all.set
ssh srx300 "cli -c 'configure exclusive; load set /var/tmp/v6-all.set; commit confirmed 5'"
# verify irb v6 addresses and RA counters (commands above), then within 5 min:
ssh srx300 "cli -c 'configure exclusive; commit'"
```

Rollback: `ssh srx300 "cli -c 'rollback 1; commit'"`.

## Known limitations

- **Dual-stack lifecycle** — this branch is the DHCPv6 client only; the
  surrounding minis / `ep-control` orchestration is out of scope.
- **Post-lease reachability** (ping/HTTP over the leased v6 address) —
  requires an upstream v6 default route on the SRX (`inet6.0` has none).
- **`domain-search` on Junos** — Junos 25.4 SRX `inet6 dhcp-attributes` has
  no `domain-search`, so SRX-served leases will carry DNS servers but no
  search list. The Kea fixture used here still exercises the search-domain
  code path.
- **No CI.** Tests are developer-invoked; there is no automated pipeline.

## Files in this directory

| File                          | Purpose                                                    |
| ------------------------------| -----------------------------------------------------------|
| `Dockerfile`                  | Debian + Kea image for running on macOS                    |
| `local-kea.sh`                | Test logic (works in-container or on a Linux host)         |
| `local-kea-docker.sh`         | macOS wrapper: cross-compile + `docker run` local-kea.sh   |
| `srx-config-v6-all.set`       | Junos config delta: DHCPv6 + RA on `irb.{1,3,5,7,9}`       |
| `README.md`                   | This file                                                  |
