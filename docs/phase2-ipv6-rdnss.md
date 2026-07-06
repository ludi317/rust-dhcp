# Phase 2 — RA / RDNSS handling for downloadable minis

**Status**: design — input for the follow-up ticket. Phase 1 (MIST-202976)
ships stateful DHCPv6 (IA_NA) and **does not** consume Router Advertisements
or RDNSS.

## The gap

Two pieces of IPv6 configuration sit outside the DHCPv6 packet flow:

- **Default route** — comes from the Router Advertisement (RA) `Router
  Lifetime` field (RFC 4861 §4.2). The kernel installs it automatically when
  `accept_ra` is set on the interface. The DHCPv6 server never advertises a
  default gateway.
- **RDNSS / DNSSL** — RFC 8106 lets RAs carry DNS servers and search lists.
  Many networks deploy SLAAC-only with RDNSS, no DHCPv6 at all. Phase 1
  ignores any RA-borne DNS information.

On the AP, the kernel handles RA processing only if `accept_ra=2` on the
interface (since the AP is also forwarding). RDNSS specifically is *not*
parsed by the Linux kernel into a userspace artifact — that requires a
userspace listener.

## Phase 1 failure mode (recap)

With Phase 1 alone, on a network with:

- **DHCPv6 + RA**: addresses + DNS come from DHCPv6; default route comes
  from the kernel's RA handling. Works.
- **DHCPv6 only, no RA**: addresses + DNS come from DHCPv6; **no default
  route**. Minis lose external connectivity. Rare in practice (any router
  emitting DHCPv6 also emits RAs).
- **SLAAC + RDNSS only**: kernel auto-configures the address from the RA
  prefix; rust-dhcp SOLICIT times out after 30s; **DNS is never written**.
  Minis lose name resolution. This is the gap Phase 2 must close.

## Option A — standalone Rust RDNSS listener

A separate binary (`rust-rdnss-listener`?) joined to the IPv6 all-nodes
multicast group `ff02::1`, parsing ICMPv6 Router Advertisements via raw
socket. On observing an RA with an RDNSS or DNSSL option, write
`<resolv-conf-path>.ra` (or merge into `.ipv6`). The orchestrator already
needs to merge `<base>.ipv4` and `<base>.ipv6` into the consumer-facing
`resolv.conf`; adding `.ra` is a minor extension.

**Pros**:
- Stays inside the Rust toolchain the team is consolidating on.
- Tight control over write semantics (path, atomicity, merging).
- Same crate workspace, sharable `dns.rs` helpers, ~300 LOC binary.
- Single deployable that the orchestrator can manage like the DHCPv4/v6
  invocations.

**Cons**:
- Yet another long-running process per netns.
- Raw socket / ICMPv6 multicast permissions need to land cleanly inside
  netns (the same problem the v6 client already solved — workable).
- We re-invent a subset of `rdnssd` / `systemd-networkd-rdnss`. Maintenance
  cost is non-zero.

**Effort**: ~30–40 h. Raw-socket setup, RA parsing (use `pnet`/`etherparse`
or hand-roll), state machine for lifetime expiry of RDNSS entries, integration
with the existing `dns.rs` split-file model.

## Option B — adopt `odhcp6c` from apfw

A parallel effort is already adding `odhcp6c` to the apfw firmware image.
`odhcp6c` is OpenWrt's IPv6 client: it handles DHCPv6 (IA_NA + IA_PD), RAs,
RDNSS, and DNSSL. Mature C codebase, well-tested.

**Pros**:
- Zero new code in rust-dhcp.
- Battle-tested in OpenWrt deployments.
- Single binary handles all of IPv6 (defaults, addresses, prefixes, DNS).
- Already entering the AP firmware via a separate effort — no incremental
  binary size hit.

**Cons**:
- Conflicts with the longer-term plan to retire udhcpc / udhcpc6 in favor
  of the Rust client. We would be re-introducing a C dependency on the IPv6
  side after we've removed it on the IPv4 side.
- Different operational surface from rust-dhcp: signals, log format,
  resolv.conf handling. Orchestrator needs two integration paths.
- Forks the team's "Rust everything" stance.

**Effort**: ~10 h to wire `odhcp6c` into the orchestrator (CLI flags,
resolv.conf merging, signal mapping). Most of the effort is owned by the
parallel apfw team.

## Option C (hybrid) — Rust DHCPv6, `odhcp6c` for RAs only

Run rust-dhcp `--ipv6` for the address lease and use `odhcp6c -R` (or
`rdnssd`) only for RA-borne DNS. Avoid the all-of-IPv6-in-C swing.

**Pros**: keeps the leasing path in Rust; satisfies RDNSS without writing
new RA-parsing code.

**Cons**: two long-running processes per netns for IPv6 alone. The split
between "who owns DNS" becomes subtle.

**Effort**: ~6 h orchestrator wiring + whatever `odhcp6c` minimal-mode
testing requires.

## Recommendation

**Option A** (standalone Rust RDNSS listener) aligns with the locked-in
direction of retiring udhcpc/udhcpc6 and consolidating on the Rust
toolchain. The effort delta vs Option C is real (~25 h) but bounds the
long-tail maintenance to a single team and language.

Defer the decision until:

1. The parallel apfw `odhcp6c` work has landed (or been canceled) — that
   collapses the relevant cost columns.
2. Real network-survey data on how many target deployments rely on RDNSS
   vs DHCPv6-served DNS. If DHCPv6 DNS dominates, the RDNSS listener can
   be lower priority.

## Coordination

- **apfw `odhcp6c` effort** — confirm scope (DHCPv6 only? RAs? RDNSS?).
  If they already ship RDNSS, Option C becomes near-free.
- **`IPVersionPreference` cloud contract** — the cloud side needs to know
  whether IPv6 means "addresses only" or "addresses + DNS via RDNSS". The
  Phase 2 choice here directly shapes that contract.
- **Orchestrator `mist-ap/ep/minis/minis.go`** — already grows a third
  invocation per netns under Option A. Confirm signal/lifecycle parity
  with the existing `--ipv4` / `--ipv6` invocations before scoping the
  ticket.

## Concrete sub-tickets (Option A)

1. **`rust-rdnss-listener` crate scaffold** — new binary in the workspace,
   raw-socket RA receive, basic option decode (Source Link-Layer Address,
   Prefix Information, RDNSS, DNSSL). ~10 h.
2. **DNS write path** — extend `dns.rs` to support an `.ra` file family.
   Merge semantics live in the orchestrator. ~4 h.
3. **Lifetime tracking** — RDNSS entries have per-server lifetimes; when
   expired, rewrite the file. ~6 h.
4. **CLI + signals** — mirror the rust-dhcp surface so the orchestrator's
   lifecycle model stays uniform. ~3 h.
5. **Manual test runbook** — extend `tests/manual/README.md` with an RA
   emitter (e.g. `radvd`) configuration. ~3 h.
6. **Orchestrator integration** — third invocation in
   `mist-ap/ep/minis/minis.go`, merging `.ipv4` + `.ipv6` + `.ra`. Sibling
   ticket owned by the Go-side team. ~6 h.

Phase 2 total estimate: ~30 h Rust + ~6 h orchestrator + parallel apfw work.
