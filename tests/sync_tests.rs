//! End-to-end integration test: two in-process nodes sync a chain over
//! the real libp2p stack (TCP + Noise + request-response sync protocol).

use std::sync::Arc;
use std::time::Duration;

use chains::crypto::keys::generate_signing_key;
use chains::models::{Body, Header};
use chains::network::Network;
use chains::storage::Storage;
use ed25519_dalek::SigningKey;
use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use tempfile::TempDir;
use tokio::sync::Mutex;

const CHAIN_LEN: u64 = 5;

fn append_block(storage: &Storage, key: &SigningKey, chain_id: [u8; 32], data: &[u8]) {
    let latest = storage.get_latest_sequence(&chain_id).unwrap();
    let sequence = latest + 1;
    let prev_hash = if sequence == 1 {
        [0u8; 32]
    } else {
        storage
            .get_header(&chain_id, latest)
            .unwrap()
            .unwrap()
            .block_id
    };
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut body = Body::new([0u8; 32], data.to_vec());
    let header = Header::new(
        chain_id,
        key.verifying_key().to_bytes(),
        sequence,
        timestamp,
        prev_hash,
        body.body_hash(),
        0,
        key,
    );
    body.block_id = header.block_id;

    storage.store_header(&chain_id, sequence, &header).unwrap();
    storage.store_body(&body.block_id, &body).unwrap();
    storage.update_latest_sequence(&chain_id, sequence).unwrap();
}

async fn make_node(dir: &TempDir) -> (Arc<Mutex<Storage>>, Network) {
    let storage = Arc::new(Mutex::new(
        Storage::new(dir.path().join("db").to_str().unwrap()).unwrap(),
    ));
    let network = Network::new(storage.clone(), dir.path().to_str().unwrap())
        .await
        .unwrap();
    (storage, network)
}

/// Drives a node's swarm until the test ends.
fn spawn_event_loop(mut network: Network) {
    tokio::spawn(async move {
        loop {
            let event = network.swarm.select_next_some().await;
            let _ = network.handle_event(event).await;
        }
    });
}

#[tokio::test]
async fn late_joiner_syncs_full_chain_from_peer() {
    let chain_id = [42u8; 32];
    let key = generate_signing_key();

    // Node A: the publisher, already holding a 5-block chain.
    let dir_a = TempDir::new().unwrap();
    let (storage_a, mut net_a) = make_node(&dir_a).await;
    {
        let s = storage_a.lock().await;
        s.create_chain(&chain_id).unwrap();
        for i in 0..CHAIN_LEN {
            append_block(&s, &key, chain_id, format!("block {}", i).as_bytes());
        }
    }

    // Wait for A's loopback listen address, then hand its swarm to a task.
    let listen_addr = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let event = net_a.swarm.select_next_some().await;
            if let SwarmEvent::NewListenAddr { address, .. } = &event {
                if address.to_string().starts_with("/ip4/127.0.0.1") {
                    break address.clone();
                }
            }
            let _ = net_a.handle_event(event).await;
        }
    })
    .await
    .expect("node A never produced a loopback listen address");
    spawn_event_loop(net_a);

    // Node B: a late joiner that knows only the chain ID and A's address.
    let dir_b = TempDir::new().unwrap();
    let (storage_b, mut net_b) = make_node(&dir_b).await;
    net_b.subscribe(&chain_id).unwrap();
    net_b.swarm.dial(listen_addr).unwrap();
    spawn_event_loop(net_b);

    // On connection, B asks A for its latest sequence, pulls the headers,
    // verifies them, and fetches each body. Wait for that to complete.
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            {
                let s = storage_b.lock().await;
                if s.get_latest_sequence(&chain_id).unwrap() == CHAIN_LEN {
                    let all_bodies_present = (1..=CHAIN_LEN).all(|seq| {
                        s.get_header(&chain_id, seq)
                            .unwrap()
                            .and_then(|h| s.get_body(&h.block_id).unwrap())
                            .is_some()
                    });
                    if all_bodies_present {
                        break;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("node B failed to sync the chain within 60s");

    // The synced replica must be cryptographically identical to the source.
    let s = storage_b.lock().await;
    for seq in 1..=CHAIN_LEN {
        let header = s.get_header(&chain_id, seq).unwrap().unwrap();
        header.verify().unwrap();
        let body = s.get_body(&header.block_id).unwrap().unwrap();
        assert_eq!(header.body_hash, body.body_hash());
        assert_eq!(body.ciphertext, format!("block {}", seq - 1).into_bytes());
    }
}
