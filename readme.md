# ⛓️ Chains: The Immutable Stream

> **A peer-to-peer, append-only event streaming protocol with zero-trust end-to-end encryption.**

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#) [![Rust Version](https://img.shields.io/badge/rust-1.75%2B-blue)](#) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](#) [![Status: Alpha](https://img.shields.io/badge/Status-Alpha-orange)](#)


## What is Chains?

Historically, distributed data has been divided into two paradigms:
1. **Static Files (BitTorrent, IPFS):** Excellent for decentralized distribution, terrible for dynamic, real-time data.
2. **Centralized Streams (Kafka, Twitch, WebSockets):** Excellent for real-time pipelines, but centralized, easily censored, and heavily reliant on expensive server infrastructure.

**Chains** bridges this gap. It introduces **Mutable Swarms**—append-only cryptographic logs hosted entirely on a peer-to-peer network. By combining Directed Acyclic Graphs (DAGs), epidemic gossip protocols, and Signal-style encryption, Chains enables real-time video streaming, massive IoT firehoses, and ghost messaging—**without a single centralized server.**

---

## Why Chains? (The Pivot)

| Feature | HTTP/WebSockets | BitTorrent / IPFS | Apache Kafka | ⛓️ **CHAINS** |
| :--- | :--- | :--- | :--- | :--- |
| **Data Type** | Mutable / Stateful | Static Files | Data Streams | **Dynamic Streams** |
| **Speed** | Real-time | Slow Ramp-up | Real-time | **Real-time** |
| **Topology** | Client-Server | P2P | Centralized Cluster | **P2P Swarm** |
| **Privacy** | Low (Server sees all) | Zero (Public Swarm IPs) | Internal / Trusted | **Zero-Trust (Onion Routed)** |
| **Cost to Scale**| Exponential (Servers) | Free | Exponential | **Inverse Scaling (Free)** |

*(Inverse Scaling: In Chains, every viewer is a relayer. The more people that watch a stream, the stronger and faster the network becomes).*

---

## Core Features

*   **⚡ Sub-Second Latency:** Rust-native async networking via QUIC (HTTP/3) over UDP prevents head-of-line blocking.
*   **🪶 Sparse Replication:** You don't need to download the whole history. Download only the "tail" of the stream for live video, or specific chunks for chat history.
*   **🔒 Zero-Trust Encryption:** 
    *   *1-to-1 DMs:* Utilizes the **Double Ratchet** algorithm (Forward Secrecy & Post-Compromise Security).
    *   *1-to-Many Streams:* Utilizes **Rotational Epoch Keys** (instantly lock out banned subscribers).
*   **🕵️ Anonymity (Streamlined Onion Routing):** Chains routes data packets through 3 anonymous hops before injecting them into the Swarm. The network sees the Exit Node, not the Publisher's IP.
*   **🗑️ Smart Garbage Collection:** Define a `TTL` (Time-to-Live) on your streams. Heavy video blocks are deleted from disk after an hour, but lightweight cryptographic headers are kept forever to prove stream integrity.

---

## Use Cases

1.  **"Ghost" Messaging (Alternative to Telegram/Signal):**
    Messages are stored on the participants' devices, linked via CRDTs. If both go offline, encrypted fragments are held by network "Relay Nodes" who can deliver the data but cannot read it.
2.  **Uncensorable Live Streaming (Alternative to Twitch):**
    A creator in a restrictive environment starts a stream. Viewers become relayers. No central server or government firewall can shut down the feed, and the creator's IP is hidden.
3.  **Serverless IoT Firehose (Alternative to AWS Kinesis):**
    Smart devices write telemetry data to a local Chain. Backend microservices seamlessly subscribe to that Chain hash and ingest the data locally, saving millions in cloud ingress costs.

---

## Architecture Overview

Chains is built on 4 technical pillars. For a deep dive, see the [Architecture Whitepaper](./docs/ARCHITECTURE.md).

1.  **Hyper-Chains (Data Layer):** Data is decoupled into lightweight **Headers** (Blake3 Hash, Ed25519 Signature, metadata) and heavyweight **Bodies** (Encrypted payload). Nodes sync state via headers in milliseconds before pulling bodies.
2.  **Blind Swarming (Network Layer):** Built on `libp2p`. Nodes discover topics via a **Kademlia DHT**, and data is propagated using **Plumtree/GossipSub** for epidemic broadcasting.
3.  **Zero-Trust Channels (Security Layer):** All data is signed via `ed25519-dalek` and encrypted via `libsodium` (XChaCha20-Poly1305). 
4.  **BitSwap 2.0 (Incentive Layer):** Nodes use local Tit-for-Tat reputation to prioritize bandwidth for peers who contribute to the swarm, with optional storage-renting mechanisms.

---

## Getting Started (Rust SDK)

*Note: Chains is currently in Alpha. The API is subject to change.*

### Installation
Add Chains to your `Cargo.toml`:
```toml
[dependencies]
chains-core = "0.1.0"
tokio = { version = "1", features = ["full"] }
```

### Basic Example: Creating and Subscribing to a Stream

```rust
use chains_core::{Node, Topic, ChainConfig};
use tokio::stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize a local Chains node (spins up QUIC + libp2p)
    let mut node = Node::new().await?;

    // 2. Create a new Encrypted Real-Time Chain (Topic)
    let topic = Topic::create(ChainConfig {
        name: "sensor-telemetry".to_string(),
        ttl_seconds: 3600, // Delete payloads after 1 hour
        is_private: true,
    });

    // 3. Get the Magnet Link / Public Key
    let invite_code = topic.public_key();
    println!("Share this topic ID: {}", invite_code);

    // 4. Append data (Like Kafka) - Async and non-blocking
    node.publish(&topic, b"{ 'temp': 22.5, 'status': 'ok' }").await?;

    // 5. Subscribe to an incoming stream
    let mut stream = node.subscribe(invite_code).await?;
    
    while let Some(block) = stream.next().await {
        println!("Received new block at sequence {}: {:?}", 
            block.header.sequence, 
            block.decrypt_body()
        );
    }

    Ok(())
}
```

---

## CLI Usage

For non-Rust developers, Chains can be run as a standalone background daemon.

```bash
# Install the CLI
cargo install chains-cli

# Start a local node (runs on UDP 4001)
chains daemon start

# Create a new text stream
chains stream create --name "My Chat" --type private

# Subscribe to a stream via its Public Key
chains stream join <PUBLIC_KEY>

# Tail a stream (like `tail -f`)
chains tail <PUBLIC_KEY>
```

---

## Tech Stack

The MVP relies on battle-tested, high-performance Rust libraries:

*   **Core Logic/Memory:** `Rust` 
*   **Networking:** `rust-libp2p` (DHT, AutoNAT, GossipSub)
*   **Transport:** `quinn` (QUIC / HTTP3)
*   **Local Storage:** `sled` or `rocksdb` (Embedded Key-Value stores)
*   **Cryptography:** `libsodium`, `ed25519-dalek`
*   **Hashing:** `blake3`
*   **Serialization:** Protocol Buffers via `prost`

---

## Contributing

We welcome contributions from the community! Chains is tackling hard problems in distributed systems, cryptography, and network engineering. 

1. Check out our [Good First Issues](https://github.com/chains-network/chains/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).
2. Read our [Contribution Guidelines](./CONTRIBUTING.md).
3. Join the Developer Discord (coming soon).

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details. 

*Privacy is a human right. Build uncompromised systems.*
