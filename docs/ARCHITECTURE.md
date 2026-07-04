
# CHAINS: The Immutable Stream

**A Peer-to-Peer, Append-Only Event Streaming Protocol with Zero-Trust End-to-End Encryption.**

## 1. Executive Summary & The Pivot

Historically, distributed data has been divided into two paradigms:

1. **Static Files (BitTorrent, IPFS):** Excellent for distribution, terrible for mutable, real-time data.
2. **Centralized Streams (Kafka, AWS Kinesis, Twitch):** Excellent for real-time data pipelines, but heavily centralized, easily censored, and privacy-invasive.

**Chains** bridges this gap. It introduces **Mutable Swarms**—append-only cryptographic logs hosted on a peer-to-peer network. By combining Directed Acyclic Graphs (DAGs), libp2p routing, Plumtree gossip protocols, and Signal-style Double Ratchet encryption, Chains enables real-time video streaming, massive IoT firehoses, and ghost messaging without a single centralized server.

---

## 2. The Four Pillars of Architecture

### Pillar I: The Data Layer (Hyper-Chains)

Instead of static files, a Chain is an infinite, append-only Merkle-Signed Log.

* **Sparse Replication:** Unlike torrents, peers subscribe to the *tail* of the stream. You don't need Block 0 to watch a live stream at Block 10,000.
* **Header/Body Decoupling:** Metadata (Headers) are segregated from Payload (Bodies). Nodes can sync the state of a stream in milliseconds before downloading heavy video or data chunks.
* **State Snapshotting (Improvement):** To prevent "infinite header" memory bloat, Chains uses Epoch Snapshots. Every 10,000 blocks, the stream state is rolled up into a cryptographic snapshot, allowing nodes to permanently prune legacy headers.

### Pillar II: The Network Layer (Blind Swarming)

Nodes dynamically discover topics via a **Kademlia Distributed Hash Table (DHT)** and propagate data via **Plumtree Gossip (Epidemic Broadcast)**.

* **Topic Routing, Not IP Routing:** Users subscribe to a cryptographic hash (the Topic ID). The network routes data based on topics, hiding consumer topography.
* **Transport:** Rust’s `tokio` asynchronous runtime over **QUIC (HTTP/3 via UDP)** prevents head-of-line blocking, allowing video frames and chat messages to drop without stalling the entire stream.

### Pillar III: The Privacy Layer (Zero-Trust Transport)

Standard P2P leaks IP addresses. Chains implements **Streamlined Onion Routing (SOR)**.

* **The 3-Hop Injection:** When a publisher broadcasts a block, it is encrypted three times. It bounces through three nodes before hitting the "Exit Node," which actually injects it into the Gossip Swarm. The swarm sees the Exit Node, not the Publisher.
* **Double Ratchet:** For private messaging, every message uses a new derived key (Forward Secrecy and Post-Compromise Security).
* **Rotational Epoch Keys:** For 1-to-Many live streams, the broadcaster generates a symmetric key, distributes it to authorized viewers, and rotates it instantly if a user is banned or their subscription expires.

### Pillar IV: The Incentive Layer (BitSwap 2.0)

To prevent network decay, Chains implements a local reputational system (Tit-for-Tat) and an optional tokenized credit system.

* **Proof-of-Relay:** Super-nodes earn credits by providing bandwidth to route Onion packets.
* **Storage Renting:** IoT devices or offline users pay the swarm to "pin" their historical blocks until they return.

---

## 3. Technical Specification (Rust Implementation)

The following schema defines the core architecture for a native Rust implementation, utilizing `serde` for serialization, `ed25519-dalek` for signatures, and `blake3` for blazing-fast hashing.

### 3.1 Data Structures

```rust
use serde::{Serialize, Deserialize};
use ed25519_dalek::{Signature, PublicKey};
use blake3::Hash;

/// The Lightweight Header: Downloaded by all nodes to verify stream integrity.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BlockHeader {
    pub block_id: Hash,           // BLAKE3 Hash of the serialized header
    pub chain_id: PublicKey,      // Ed25519 Public Key of the Stream Topic
    pub author_id: PublicKey,     // Ed25519 Public Key of the Sender
    pub sequence: u64,            // Monotonically increasing sequence
    pub timestamp: u64,           // Unix epoch timestamp
    pub prev_hash: Hash,          // Hash of the previous block's header
    pub body_hash: Hash,          // BLAKE3 Hash of the encrypted body
    pub ttl: u32,                 // Time-To-Live in seconds (0 = forever)
    pub signature: Signature,     // Ed25519 Signature of (prev_hash + body_hash + sequence)
}

/// The Heavyweight Body: Downloaded only if the peer requires the actual data.
#[derive(Serialize, Deserialize, Clone)]
pub struct BlockBody {
    pub block_id: Hash,           // Links back to the Header
    pub encryption_algo: String,  // e.g., "XChaCha20-Poly1305"
    pub nonce: [u8; 24],          // Initialization vector
    pub ciphertext: Vec<u8>,      // The encrypted payload (Video, Chat, IoT data)
}

/// The local database representation (Stored via `sled` or `rocksdb`)
pub struct ChainState {
    pub headers: sled::Tree,
    pub bodies: sled::Tree,
    pub snapshots: sled::Tree,
}
```

### 3.2 Multi-Writer DAG Resolution (Chat Rooms)

If Alice and Bob type a message simultaneously in a group chat, they both attempt to be `Sequence: 51`. A linear blockchain would fork and fail.
**The Solution:** Every user writes to their *own* Chain. A "Room" is a collection of Topic IDs. The UI layer merges these chains using **Vector Clocks / CRDTs (Conflict-Free Replicated Data Types)** to guarantee the exact same message ordering on every participant's screen.

---

## 4. Node Lifecycle & State Machine

Every Chains Node runs an asynchronous state machine driven by `libp2p`.

### State 1: Discovery (`Kademlia DHT`)

1. Application requests to join `chain://<topic_public_key>`.
2. Node hashes the Public Key to create a `PeerId`.
3. Node queries the DHT: `get_providers(topic_hash)`.
4. DHT returns a list of active IP:Port addresses.

### State 2: Handshake & Sync (`Asynchronous X3DH`)

1. Node connects via QUIC and requests the remote peer's latest `sequence`.
2. **Comparison:**
   * If local sequence is `50` and remote is `60`, the node triggers **Catch-up Mode**.
3. **Sparse Pull:**
   * Node sends `GET_HEADERS { start: 51, end: 60 }`.
   * Cryptographically verifies the `prev_hash` chain and the Ed25519 signatures.
   * If this is a video stream, the node ignores bodies `51` through `57` (saving gigabytes) and only requests `GET_BODY {58, 59, 60}` to fill the live buffer.

### State 3: Real-Time Gossip (`Plumtree/GossipSub`)

1. Node shifts from "Pull" to "Push" mode.
2. When Publisher creates Block `61`, it is pushed to the node.
3. Node immediately forwards the Header to its connected peers, *then* begins decrypting the Body.
4. Result: Sub-second latency worldwide.

---

## 5. Security & Cryptographic Flow

Do not roll your own crypto. Chains relies exclusively on the **libsodium** primitives and standard signal protocols.

### 5.1 Identity

* **Key Pair:** `Ed25519` (Fast, 32-byte keys).
* Your Private Key is your account. There are no passwords.

### 5.2 Private Messaging (The Double Ratchet)

* **Use Case:** 1-to-1 or small group DMs.
* **Initial Setup:** Extended Triple Diffie-Hellman (X3DH). Sender fetches offline Receiver’s "Pre-Key" from the DHT to establish the `Root Key`.
* **Ratchet:** With every message, the `Chain Key` is hashed (HMAC-SHA256) to produce a one-time `Message Key`, then the `Chain Key` is stepped forward. Even if a device is seized, old messages cannot be decrypted.

### 5.3 Live Streaming (Rotational Epoch Keys)

* **Problem:** You cannot run the Double Ratchet on 10,000 viewers.
* **Solution:** Broadcaster generates `EpochKey_1` (XChaCha20-Poly1305).
* Broadcaster uses asymmetric crypto to send `EpochKey_1` to all paying subscribers.
* Broadcaster encrypts video frames *once* using `EpochKey_1` and gossips it to the swarm.
* **Rotation:** If User X is banned, the Broadcaster generates `EpochKey_2`, distributes it to everyone *except* User X, and begins encrypting new frames. User X receives the frames (P2P is open), but it renders as static.

### 5.4 Anonymity (Streamlined Onion Routing)

To protect Streamers (e.g., dissidents) from state-actor tracking.

```text
Publisher [Payload]
  │
  ├── Encrypts for Exit Node Z (Instruction: Gossip to #FreedomStream)
  ├── Encrypts for Middle Node Y (Instruction: Send to Z)
  └── Encrypts for Entry Node X (Instruction: Send to Y)

Network Path: Publisher ---> Node X ---> Node Y ---> Node Z ---> Swarm
```

* **Node X** knows the Publisher's IP, but not what the data is.
* **Node Z** knows the data is a video frame for `#FreedomStream`, but thinks Node Y is the publisher.

---

## 6. The "Frame 402" Stress Test Simulation

Let us trace exactly how a video frame traverses the Chains architecture.

1. **00ms - Capture:** Alice's camera generates raw frame 402.
2. **05ms - Encryption:** The Chains Client encrypts the 50KB chunk using the current symmetric `EpochKey`.
3. **10ms - Packaging:** The client generates `Header 402`, pointing `prev_hash` to `Header 401`. Alice signs the Header with her Ed25519 private key.
4. **15ms - The Cloak:** The 50KB block is wrapped in 3 layers of Onion Encryption via chosen peers X, Y, and Z.
5. **20ms - Injection:** Alice pushes the payload to Node X over QUIC.
6. **60ms - Unpeeling:** The packet traverses X -> Y -> Z. Node Z decrypts the final layer, discovering a valid Chains Block for topic `#FreedomStream`.
7. **65ms - Epidemic Spread:** Node Z gossips `Header 402` to its 8 peers. They verify Alice's signature. It is valid. They pull the Body.
8. **200ms - Saturation:** 1 -> 8 -> 64 -> 512 -> 4,096 nodes have the block.
9. **210ms - Consumption:** Bob in New York receives the block, verifies the header, uses his valid `EpochKey` to decrypt the XChaCha20-Poly1305 payload, and the frame renders in his media player.
10. **1 Hour Later - Garbage Collection:** Because Alice set `ttl: 3600` on video chunks, nodes across the world delete `Body 402` from their local databases to save disk space, but they retain `Header 402` to mathematically prove the integrity of `Header 403`.

---

## 7. Recommended Tech Stack for MVP

If building this today, the following Rust-centric stack guarantees memory safety, high concurrency, and interoperability:

| Component                | Technology                        | Rationale                                                                                  |
| :----------------------- | :-------------------------------- | :----------------------------------------------------------------------------------------- |
| **Language**       | Rust                              | Zero-cost abstractions, memory safety, required for blazing-fast cryptographic operations. |
| **Networking**     | `libp2p` (Rust)                 | Built-in Kademlia DHT, GossipSub, mDNS, and NAT Hole Punching (AutoNAT).                   |
| **Transport**      | QUIC (`quinn` crate)            | UDP-based multiplexing prevents stream blocking if a packet is lost.                       |
| **Local Database** | `sled` or `rocksdb`           | High-performance, embedded Key-Value stores for caching Chains to disk.                    |
| **Cryptography**   | `libsodium` / `ed25519-dalek` | Battle-tested, side-channel resistant cryptographic suites.                                |
| **Hashing**        | BLAKE3                            | Orders of magnitude faster than SHA-256; critical for real-time video hashing.             |
| **Serialization**  | Protocol Buffers /`prost`       | Language-agnostic, hyper-compact binary encoding for network transmission.                 |

---

HTTP/HTTPS and Chains are designed for fundamentally different paradigms of data transfer. To understand why Chains won't kill HTTP—but will dominate its real-time counterparts—we have to look at the architectural differences.

---

### Why Chains Cannot Replace HTTP

**1. The Request-Response vs. Pub-Sub Paradigm**

* **HTTP is Request-Response:** It is designed for discrete, stateless interactions. A client asks for a specific resource (`GET /index.html`), and a server returns it. It is incredibly efficient for loading static pages, submitting a login form, or querying a REST API.
* **Chains is Pub-Sub (Publish/Subscribe):** Chains is designed for continuous, infinite streams of data. If you just want to load a simple Wikipedia article, spinning up a Kademlia DHT query, syncing cryptographic headers, and establishing a swarm connection is massive overkill and adds unnecessary latency.

**2. Data Mutability (CRUD vs. Append-Only)**

* **HTTP supports CRUD:** Create, Read, Update, Delete. If you want to change a user's profile picture, HTTP sends a `PUT` request to overwrite the old one on the server.
* **Chains is Append-Only:** Because Chains relies on Merkle-signed DAGs, you cannot "edit" past data. To change a profile picture in Chains, you would have to append a new block saying "Update Profile Picture to X," and the client application would have to read the whole history to determine the current state (Event Sourcing). This is brilliant for chat logs or financial ledgers, but terrible for simple website states.

**3. Latency in Single Queries**

* **HTTP:** Client connects directly to the Server IP. Time to First Byte (TTFB) is often under 50ms.
* **Chains:** To protect privacy and prevent censorship, Chains uses Streamlined Onion Routing (SOR) and DHT lookups. Finding the stream and bouncing the packet through 3 anonymous nodes inherently adds 100ms–300ms of latency.

---

### What Chains *Will* Replace (The "Real-Time" Web)

While it won't replace standard web browsing, Chains is engineered to completely replace the **centralized, stateful, real-time protocols** that developers currently shoehorn into HTTP.

**1. It Replaces WebSockets and Socket.io**

* **The HTTP Problem:** WebSockets require persistent, stateful connections to a centralized server. If 100,000 users join a chat room, the server must hold 100,000 open TCP connections. This is wildly expensive (requiring massive AWS load balancers).
* **The Chains Solution:** Serverless Pub-Sub. Users subscribe to a topic hash. Through the Epidemic Gossip protocol, 100,000 users distribute the chat messages among themselves. The developer pays $0 in server costs.

**2. It Replaces HLS / WebRTC (Live Streaming)**

* **The HTTP Problem:** HLS (used by Twitch/YouTube) requires massive centralized Content Delivery Networks (CDNs). A single server failure or a government firewall block can instantly kill the stream.
* **The Chains Solution:** Inverse Scaling. In Chains, every viewer acts as a relay node. The more people watch a stream, the more bandwidth the swarm has, making it uncensorable and infinitely scalable without a central CDN.

**3. It Replaces Backend Webhooks & APIs (Kafka / Firebase)**

* **The HTTP Problem:** IoT devices (smart cars, sensors) currently use HTTP/MQTT to constantly ping a central cloud database (like AWS) with telemetry data.
* **The Chains Solution:** Devices write to a local Chain. Backend microservices seamlessly subscribe to that Chain and ingest the data locally. It creates a serverless, end-to-end encrypted nervous system.

---

### The Symbiotic Future (How they work together)

In a practical application (like a decentralized alternative to Discord or Twitch), developers will not choose one over the other. They will use both:

1. **HTTPS (The Delivery Mechanism):** The user navigates to `https://my-app.com`. A traditional web server instantly delivers the frontend UI (HTML, CSS, React, WebAssembly) in 50 milliseconds.
2. **Chains (The Data Pipeline):** Once the web app loads in the browser, the WebAssembly (WASM) code initializes the **Chains Client**. The application connects to the P2P swarm, discovers peers, and begins piping in real-time video, chat, and event data—completely bypassing the web server.

**Summary:** HTTP/HTTPS remains the undisputed king of fetching static/mutable documents. Chains is the new sovereign of real-time, peer-to-peer data streams.

## 8. Implementation Roadmap

### Phase 1: The Core Protocol (Local CLI)

* Define the `Header` and `Body` Protocol Buffer schemas.
* Implement BLAKE3 hashing and Ed25519 signing.
* Build a local Sled DB wrapper to allow append-only writes.
* *Goal:* Two CLI instances on the same localhost can sync a text-based DAG securely.

### Phase 2: The Blind Swarm (Networking)

* Integrate `rust-libp2p`.
* Implement Kademlia DHT for Peer/Topic discovery.
* Implement GossipSub for real-time header pushing.
* *Goal:* Two computers across the internet can sync the Chain dynamically without a tracker server.

### Phase 3: The Encryption Engine & Pruning

* Implement X3DH and the Double Ratchet for private Chains.
* Implement Rotational Epoch Keys for public streaming Chai
* ns.
* Implement the Garbage Collector (TTL pruning and State Snapshotting).
* *Goal:* Fully encrypted streams that don't crash the user's hard drive.

### Phase 4: Application Layer (SDK & UI)

* Compile the Rust core to WebAssembly (WASM) or package it as a daemon via FFI.
* Build a React/Tauri desktop application utilizing the Chains local daemon.
* Implement "Ghost Chat" and "Live Video" UI interfaces.

---

*Chains takes the decentralized resilience of BitTorrent, the real-time pipeline power of Kafka, and the uncompromising security of Signal, weaving them together into the ultimate protocol for the next generation of the web.*
