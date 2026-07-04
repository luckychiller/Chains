# ⛓️ Chains — Project Plan & Milestones

> **Mission:** Make real-time data streams as unstoppable as BitTorrent, as fast as Kafka, and as private as Signal — with no servers, no gatekeepers, no single point of failure.

This plan turns the [architecture whitepaper](overview.md) into a sequence of concrete, verifiable milestones. Each milestone has a **Definition of Done** — a demo or test you can actually run. We only move forward when the previous layer is trustworthy, because every layer above depends on it.

---

## Where We Are Today (July 2026)

**Done (Phases 1–3 of the original roadmap):**
- ✅ Core protocol: Header/Body decoupling, BLAKE3 hashing, Ed25519 signing, sled storage (`src/models`, `src/storage`)
- ✅ P2P networking: libp2p over TCP + Noise + Yamux, Kademlia DHT, GossipSub, mDNS local discovery, request-response sync protocol (`src/network`)
- ✅ Encryption engine: X3DH + Double Ratchet for 1-to-1, Rotational Epoch Keys for 1-to-many (`src/crypto`)
- ✅ TTL garbage collection + state snapshotting every 10k blocks (`src/storage/gc.rs`)
- ✅ CLI with daemon REPL (`src/cli`)

**Done (Milestone 0, July 2026):**
- ✅ Test suite: 55 tests across crypto, data layer, storage, GC, plus a real two-node libp2p sync integration test and property-based serialization tests (`tests/`)
- ✅ CI: GitHub Actions running tests (Linux + Windows), `clippy -D warnings`, `cargo fmt --check` (`.github/workflows/ci.yml`)
- ✅ Repo hygiene: LICENSE (MIT), CONTRIBUTING.md, `docs/ARCHITECTURE.md`, `.gitignore` covering `*.key` and `*.db/`
- ✅ Three real bugs found and fixed by the M0 test pass (see below)

**Honest gaps:**
- ❌ TCP transport (whitepaper promises QUIC)
- ❌ No NAT traversal / bootstrap nodes — works on LAN via mDNS only
- ❌ No onion routing (Pillar III is unimplemented)
- ❌ No CRDT multi-writer rooms
- ❌ No SDK, no WASM, no UI, no incentive layer
- ⚠️ Double Ratchet skipped-message keys are a stub — out-of-order message delivery is not yet supported (matters once real network jitter arrives; fold into M1/M4)

---

## Milestone 0 — Bedrock: Trust the Code We Have ✅ *(completed 2026-07-04)*
*Theme: A protocol nobody can verify is a protocol nobody can trust.*

Cryptographic and distributed-systems code without tests is a liability. Before adding features, we prove what exists works.

**Deliverables**
- [x] Unit tests for the crypto layer: ratchet round-trips and multi-round ping-pong, epoch rotation locks out banned keys, X3DH agreement symmetry (`tests/crypto_tests.rs`)
- [x] Unit tests for the data layer: header signing/verification, chain linkage (`prev_hash`), tamper detection, sled persistence round-trips (`tests/models_tests.rs`, `tests/storage_tests.rs`)
- [x] Integration test: two in-process nodes sync a chain end-to-end over real libp2p — headers + bodies (`tests/sync_tests.rs`)
- [x] GC tests: TTL pruning deletes bodies but preserves headers; snapshot-gated header pruning (`tests/gc_tests.rs`)
- [x] Property-based tests (`proptest`) for serialization round-trips (`tests/proptest_serialization.rs`)
- [x] CI pipeline (GitHub Actions): `cargo test` on Linux + Windows, `cargo clippy -- -D warnings`, `cargo fmt --check`
- [x] `LICENSE` (MIT), `CONTRIBUTING.md`, `overview.md` → `docs/ARCHITECTURE.md` — every README link resolves
- [x] `.gitignore` for `*.db/`, `*.key` (the private `node.key` in the repo root can now never be committed)

**Bugs found and fixed by this milestone — the reason M0 existed:**
1. **Header signature only covered `prev_hash + body_hash + sequence`.** An attacker could alter `timestamp`, `ttl`, or `chain_id` and recompute the block ID without detection. The signature now covers every header field. (`src/models/header.rs`)
2. **Storage keys used unpadded hex sequence numbers**, so sled returned block 16 before block 2 and `get_chain` failed for any chain longer than 15 blocks. Keys are now zero-padded. (`src/storage/mod.rs`)
3. **Double Ratchet desynced on the second round-trip** of a conversation: a DH ratchet step kept the stale send chain instead of replacing it. Ping-pong messaging now works indefinitely, with a regression test. (`src/crypto/ratchet.rs`)

**Definition of Done — met:** 55 tests pass (`cargo test --all-targets`), clippy clean with warnings-as-errors, formatting canonical; CI runs all three gates on every push.

---

## Milestone 1 — The Real Internet: Beyond the LAN
*Theme: Two strangers, two continents, zero configuration.*

Right now Chains works between machines that can already see each other. The internet is hostile: NATs, firewalls, churn. This milestone makes discovery and connectivity real.

**Deliverables**
- [ ] QUIC transport (`libp2p-quic`) with TCP fallback — fulfils the whitepaper's head-of-line-blocking promise
- [ ] Bootstrap node support: a well-known peer list + `chains bootstrap` command to run one
- [ ] Kademlia provider records: publish "I host chain X" to the DHT; `get_providers` on subscribe
- [ ] NAT traversal: AutoNAT + relay (libp2p circuit relay v2) + DCUtR hole punching
- [ ] Peer persistence: remember good peers across restarts for fast rejoin
- [ ] Connection health: reconnect logic, exponential backoff, peer scoring for gossipsub

**Definition of Done:** A node behind a home NAT in one country subscribes to a chain published behind a NAT in another country, using only the chain ID and a public bootstrap node — and receives new blocks in under a second.

---

## Milestone 2 — The Living Stream: Sparse Replication at Scale
*Theme: Watch block 10,000 without downloading block 0.*

This is Chains' signature idea — subscribe to the *tail*. Make it real and prove it under load.

**Deliverables**
- [ ] Tail-sync mode: new subscriber fetches only the latest snapshot + last N headers, verifies from the snapshot forward
- [ ] Range requests: `GET_HEADERS {start, end}` and selective `GET_BODY` batching in the sync protocol
- [ ] Backpressure & flow control: bounded queues so a slow peer can't stall the swarm
- [ ] Verified snapshots: snapshot includes a signed digest so late joiners don't need genesis
- [ ] Benchmark suite: measure blocks/sec throughput and propagation latency across 10, 50, 100 simulated nodes (e.g. `testground`-style local harness or docker-compose swarm)
- [ ] Publish the numbers in `docs/BENCHMARKS.md` — honest performance data builds credibility

**Definition of Done:** A 100-node simulated swarm sustains a 1 MB/s stream; a cold node joins mid-stream and is live within 3 seconds without fetching history.

---

## Milestone 3 — The Cloak: Streamlined Onion Routing
*Theme: The swarm sees the exit node, never the publisher.*

Pillar III of the architecture, currently unbuilt. This is what makes Chains matter for people whose safety depends on it.

**Deliverables**
- [ ] SOR circuit construction: publisher selects 3 relay peers, wraps blocks in 3 layers (X25519 + XChaCha20-Poly1305)
- [ ] Relay protocol: peel-and-forward behaviour with no knowledge of origin
- [ ] Exit-node injection: final hop publishes to gossipsub as if it were the author (signature still proves authorship, IP proves nothing)
- [ ] Circuit rotation + cover-traffic padding options (make timing correlation harder)
- [ ] Threat-model document `docs/THREAT_MODEL.md`: what SOR does and *does not* protect against — honesty here is a feature
- [ ] Toggle: anonymity is opt-in per chain (latency vs privacy trade-off is the user's choice)

**Definition of Done:** In a test swarm with packet capture on every node, no node except the entry hop can associate the publisher's IP with the published chain; latency overhead is documented.

---

## Milestone 4 — The Room: Multi-Writer CRDTs
*Theme: One chain per voice, one merged view for everyone.*

Single-writer chains are a ledger. Multi-writer rooms are a *conversation* — the foundation of Ghost Chat.

**Deliverables**
- [ ] Room abstraction: a room = a set of chain IDs + membership metadata
- [ ] Causal ordering: vector clocks (or Lamport + tiebreak on block hash) merging N chains into one deterministic timeline
- [ ] Room membership: invite blocks, join/leave, membership proofs
- [ ] Group encryption: sender-keys pattern (each member encrypts with their epoch key, distributed via pairwise ratchets) — the Signal-style answer to group E2EE
- [ ] `chains room` CLI commands: create, invite, join, send, tail

**Definition of Done:** Three nodes in a room send messages concurrently while one is offline; when it reconnects, all three converge to the identical message order, verified by an automated test.

---

## Milestone 5 — The Doorway: SDK & Bindings
*Theme: If only we can build on Chains, Chains dies with us.*

Impact comes from other builders. Make the core embeddable everywhere.

**Deliverables**
- [ ] Split crates: `chains-core` (protocol, no I/O opinions), `chains-node` (networking + storage), `chains-cli`
- [ ] Clean async Rust API matching the README's promised `Node::new() / Topic::create / append / subscribe` shape
- [ ] Local daemon API: JSON-RPC or gRPC over a local socket so any language can drive a node
- [ ] WASM build of `chains-core` (crypto + verification in the browser; networking via WebRTC/WebTransport is stretch)
- [ ] Language bindings: JavaScript/TypeScript first (npm package wrapping the daemon API), Python second
- [ ] Publish `chains-core` 0.1.0 to crates.io with docs.rs documentation and 3 runnable examples

**Definition of Done:** A developer who has never seen this repo follows a 10-minute quickstart and builds a working pub-sub app in TypeScript against a local Chains daemon.

---

## Milestone 6 — The Proof: Flagship Applications
*Theme: Nobody adopts a protocol. They adopt an experience.*

Two demos that each make one pillar undeniable.

**Deliverables**
- [ ] **Ghost Chat** (Tauri + React desktop app): E2EE 1-to-1 and room messaging, offline delivery via relay peers, disappearing messages via TTL — the Double Ratchet + CRDT showcase
- [ ] **Firehose** (CLI/TUI demo): an IoT-style telemetry generator streaming thousands of events/sec to live subscribers with TTL pruning — the Kafka-replacement showcase
- [ ] *Stretch:* **Open Signal** — live video streaming demo over epoch keys (even 480p over a 10-node swarm is a headline)
- [ ] Demo video / GIFs in the README

**Definition of Done:** A non-technical person installs Ghost Chat on two laptops and exchanges encrypted messages across the internet without ever seeing the word "server."

---

## Milestone 7 — The Economy: Incentives & Resilience
*Theme: A network that pays its own rent.*

Pillar IV. Deliberately last: incentive design without a working network is speculation.

**Deliverables**
- [ ] Tit-for-tat bandwidth accounting: track bytes served/received per peer, prioritize reciprocators
- [ ] Relay reputation: local scoring of onion-relay reliability
- [ ] Storage pinning contracts: "hold my blocks while I'm offline" negotiation between peers
- [ ] Sybil-resistance analysis in the threat model
- [ ] *Deliberately deferred:* any token. Local reputation first; tokenize only if the network demands it.

**Definition of Done:** In a simulated swarm with 30% freeloaders, contributing nodes measurably out-perform freeloaders in stream quality, and the network stays healthy.

---

## Milestone 8 — The World: Launch & Community
*Theme: Ship it where the people are.*

**Deliverables**
- [ ] Security review pass: at minimum a structured self-audit of the crypto layer against the threat model; ideally one external reviewer
- [ ] `docs/`: protocol specification (so others can build compatible implementations), architecture, quickstart, FAQ
- [ ] Public bootstrap infrastructure (2–3 cheap VPS bootstrap/relay nodes)
- [ ] Binary releases: Windows/macOS/Linux via GitHub Releases + `cargo install chains`
- [ ] Launch posts: Show HN, r/rust, r/selfhosted, lobste.rs — lead with the working demo, not the whitepaper
- [ ] Contribution guide, good-first-issues, and a public roadmap (this file, kept honest)

**Definition of Done:** Strangers are running nodes we don't control, and the first outside pull request is merged.

---

## Sequencing & Principles

```
M0 Bedrock ──► M1 Real Internet ──► M2 Sparse Replication ──► M3 Onion Routing ─┐
                                          │                                      ├──► M6 Flagship Apps ──► M7 Incentives ──► M8 Launch
                                          └──► M4 CRDT Rooms ──► M5 SDK ─────────┘
```

- **Every milestone ends in something you can run.** No milestone is "done" on code alone.
- **Tests land with features, not after.** M0 sets the standard; we never regress it.
- **Honesty is strategy.** Documented limitations (threat model, benchmarks) earn more trust than promises.
- **Don't roll our own crypto.** Compose audited primitives (`ed25519-dalek`, `chacha20poly1305`, `x25519-dalek`) exactly as the whitepaper prescribes.
- **The demo is the marketing.** M6 is what the world will judge us by; everything before it is in service of that moment.

## Suggested Next Action

**Milestone 0 is done.** Next up is **Milestone 1 — The Real Internet**: QUIC transport, bootstrap nodes, and NAT traversal, so two strangers on two continents can sync a chain with nothing but a chain ID. Along the way, implement real skipped-message-key handling in the Double Ratchet (currently a stub) — the moment messages cross the real internet, they *will* arrive out of order.
