use libp2p::{
    swarm::{Swarm, SwarmEvent},
    identity::Keypair, PeerId, StreamProtocol,
    kad, gossipsub, mdns, identify,
    request_response,
    tcp, noise, yamux,
};
use std::time::Duration;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::models::{Header, Body, ChainsResult};
use crate::storage::Storage;
use crate::network::protocol::{GossipMessage, SyncRequest, SyncResponse, CHAINS_PROTOCOL, SYNC_PROTOCOL};
use crate::network::behavior::{ChainsBehaviour, ChainsBehaviourEvent};

pub struct Network {
    pub peer_id: PeerId,
    pub swarm: Swarm<ChainsBehaviour>,
    storage: Arc<Mutex<Storage>>,
    subscriptions: Vec<[u8; 32]>,
}

fn topic_for_chain(chain_id: &[u8; 32]) -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(format!("chain:{}", hex::encode(chain_id)))
}

impl Network {
    pub async fn new(storage: Arc<Mutex<Storage>>, data_dir: &str) -> ChainsResult<Self> {
        let keypair = load_or_create_p2p_keypair(data_dir)?;
        let peer_id = keypair.public().to_peer_id();

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| -> ChainsResult<ChainsBehaviour> {
                let kademlia = {
                    let mut cfg = kad::Config::default();
                    cfg.set_query_timeout(Duration::from_secs(10));
                    let store = kad::store::MemoryStore::new(key.public().to_peer_id());
                    kad::Behaviour::with_config(key.public().to_peer_id(), store, cfg)
                };

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub::Config::default(),
                )
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                    format!("gossipsub: {}", e).into()
                })?;

                let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

                let identify = identify::Behaviour::new(
                    identify::Config::new(CHAINS_PROTOCOL.into(), key.public()),
                );

                let sync = request_response::cbor::Behaviour::new(
                    [(StreamProtocol::new(SYNC_PROTOCOL), request_response::ProtocolSupport::Full)],
                    request_response::Config::default(),
                );

                Ok(ChainsBehaviour { kademlia, gossipsub, mdns, identify, sync })
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

        Ok(Network { peer_id, swarm, storage, subscriptions: Vec::new() })
    }

    pub fn subscribe(&mut self, chain_id: &[u8; 32]) -> ChainsResult<()> {
        let topic = topic_for_chain(chain_id);
        self.swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
        if !self.subscriptions.contains(chain_id) {
            self.subscriptions.push(*chain_id);
        }
        Ok(())
    }

    pub fn publish_block(&mut self, header: &Header, body: &Body) -> ChainsResult<()> {
        let topic = topic_for_chain(&header.chain_id);
        let msg = GossipMessage::Block(header.clone(), body.clone());
        let data = bincode::serialize(&msg)?;
        self.swarm.behaviour_mut().gossipsub.publish(topic, data)?;
        Ok(())
    }

    pub fn advertise_on_dht(&mut self, chain_id: &[u8; 32]) {
        let key = kad::RecordKey::new(&chain_id);
        let _ = self.swarm.behaviour_mut().kademlia.start_providing(key);
    }

    pub fn bootstrap_kademlia(&mut self) {
        let _ = self.swarm.behaviour_mut().kademlia.bootstrap();
    }

    pub async fn handle_event(
        &mut self,
        event: SwarmEvent<ChainsBehaviourEvent>,
    ) -> ChainsResult<()> {
        match event {
            SwarmEvent::Behaviour(ChainsBehaviourEvent::Gossipsub(
                gossipsub::Event::Message { message, .. },
            )) => {
                if let Err(e) = self.handle_gossip_message(message).await {
                    eprintln!("[p2p] gossip error: {}", e);
                }
            }

            SwarmEvent::Behaviour(ChainsBehaviourEvent::Sync(
                request_response::Event::Message { peer, message, .. },
            )) => {
                self.handle_sync_message(peer, message).await?;
            }

            SwarmEvent::Behaviour(ChainsBehaviourEvent::Mdns(
                mdns::Event::Discovered(list),
            )) => {
                for (peer, addr) in list {
                    self.swarm.behaviour_mut().kademlia.add_address(&peer, addr);
                }
            }

            SwarmEvent::NewListenAddr { address, .. } => {
                println!("[p2p] listening on {}", address);
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                println!("[p2p] connected to peer: {:?}", peer_id);
                for chain_id in &self.subscriptions.clone() {
                    self.swarm.behaviour_mut().sync.send_request(
                        &peer_id,
                        SyncRequest::GetLatestSequence { chain_id: *chain_id },
                    );
                }
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                println!("[p2p] disconnected from peer: {:?}", peer_id);
            }

            _ => {}
        }
        Ok(())
    }

    async fn handle_sync_message(
        &mut self,
        peer: PeerId,
        message: request_response::Message<SyncRequest, SyncResponse>,
    ) -> ChainsResult<()> {
        match message {
            request_response::Message::Request { request, channel, .. } => {
                let response = match request {
                    SyncRequest::GetLatestSequence { chain_id } => {
                        let storage = self.storage.lock().await;
                        match storage.get_latest_sequence(&chain_id) {
                            Ok(sequence) => SyncResponse::LatestSequence { chain_id, sequence },
                            Err(e) => SyncResponse::Error(e.to_string()),
                        }
                    }
                    SyncRequest::GetHeaders { chain_id, start_seq, end_seq } => {
                        let storage = self.storage.lock().await;
                        let mut headers = Vec::new();
                        for seq in start_seq..=end_seq {
                            if let Ok(Some(header)) = storage.get_header(&chain_id, seq) {
                                headers.push(header);
                            } else {
                                break;
                            }
                        }
                        SyncResponse::Headers(headers)
                    }
                    SyncRequest::GetBody { block_id } => {
                        let storage = self.storage.lock().await;
                        match storage.get_body(&block_id) {
                            Ok(body) => SyncResponse::Body(body),
                            Err(e) => SyncResponse::Error(e.to_string()),
                        }
                    }
                };
                let _ = self.swarm.behaviour_mut().sync.send_response(channel, response);
            }
            request_response::Message::Response { response, .. } => {
                match response {
                    SyncResponse::LatestSequence { chain_id, sequence: remote_seq } => {
                        let storage = self.storage.lock().await;
                        let local_seq = storage.get_latest_sequence(&chain_id).unwrap_or(0);

                        if remote_seq > local_seq {
                            println!("[p2p] peer {:?} is ahead on chain {} ({} > {}). Requesting headers...",
                                peer, hex::encode(&chain_id[..4]), remote_seq, local_seq);

                            self.swarm.behaviour_mut().sync.send_request(
                                &peer,
                                SyncRequest::GetHeaders {
                                    chain_id,
                                    start_seq: local_seq + 1,
                                    end_seq: remote_seq,
                                },
                            );
                        }
                    }
                    SyncResponse::Headers(headers) => {
                        if headers.is_empty() { return Ok(()); }
                        println!("[p2p] received {} headers for sync from {:?}", headers.len(), peer);

                        let storage = self.storage.lock().await;
                        for header in headers {
                            let chain_id = header.chain_id;
                            let seq = header.sequence;

                            let local_latest = storage.get_latest_sequence(&chain_id)?;
                            if seq > local_latest {
                                if let Err(e) = header.verify() {
                                    eprintln!("[p2p] invalid header in sync: {}", e);
                                    continue;
                                }

                                storage.store_header(&chain_id, seq, &header)?;
                                storage.update_latest_sequence(&chain_id, seq)?;
                                println!("[p2p] synced header {} for chain {}", seq, hex::encode(&chain_id[..4]));

                                self.swarm.behaviour_mut().sync.send_request(
                                    &peer,
                                    SyncRequest::GetBody { block_id: header.block_id },
                                );
                            }
                        }
                    }
                    SyncResponse::Body(body) => {
                        if let Some(body) = body {
                            println!("[p2p] received body for block {} from {:?}", hex::encode(&body.block_id[..4]), peer);
                            let storage = self.storage.lock().await;
                            storage.store_body(&body.block_id, &body)?;
                        }
                    }
                    SyncResponse::Error(e) => {
                        eprintln!("[p2p] sync error from peer {:?}: {}", peer, e);
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_gossip_message(
        &mut self,
        msg: gossipsub::Message,
    ) -> ChainsResult<()> {
        let gossip: GossipMessage = match bincode::deserialize(&msg.data) {
            Ok(m) => m,
            Err(_) => return Ok(()),
        };

        match gossip {
            GossipMessage::Block(header, body) => {
                if let Err(e) = header.verify() {
                    eprintln!("[p2p] invalid block: {}", e);
                    return Ok(());
                }
                if header.body_hash != body.body_hash() {
                    eprintln!("[p2p] body hash mismatch");
                    return Ok(());
                }

                let storage = self.storage.lock().await;
                if !storage.chain_exists(&header.chain_id)? {
                    storage.create_chain(&header.chain_id)?;
                    println!("[p2p] new chain: {}", hex::encode(&header.chain_id[..8]));
                }

                let latest = storage.get_latest_sequence(&header.chain_id)?;
                if header.sequence <= latest {
                    return Ok(());
                }

                storage.store_header(&header.chain_id, header.sequence, &header)?;
                storage.store_body(&body.block_id, &body)?;
                if header.sequence > latest {
                    storage.update_latest_sequence(&header.chain_id, header.sequence)?;
                }

                let text = String::from_utf8_lossy(&body.ciphertext);
                println!(
                    "[p2p] block {} on chain {}: {:?}",
                    header.sequence,
                    hex::encode(&header.chain_id[..8]),
                    if text.len() > 60 { format!("{}...", &text[..60]) } else { text.to_string() },
                );
            }
        }
        Ok(())
    }
}

fn load_or_create_p2p_keypair(data_dir: &str) -> ChainsResult<Keypair> {
    use std::path::Path;
    use std::fs;
    let path = if data_dir.is_empty() || data_dir.ends_with("chains.db") {
        let parent = Path::new(data_dir).parent().unwrap_or(Path::new("."));
        parent.join("p2p.key")
    } else {
        Path::new(data_dir).join("p2p.key")
    };
    if let Ok(data) = fs::read(&path) {
        if let Ok(kp) = Keypair::from_protobuf_encoding(&data) {
            return Ok(kp);
        }
    }
    let kp = Keypair::generate_ed25519();
    fs::write(&path, kp.to_protobuf_encoding().map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?)?;
    Ok(kp)
}
