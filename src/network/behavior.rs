use libp2p::{
    kad, gossipsub, mdns, identify, request_response,
    swarm::NetworkBehaviour,
};
use crate::network::protocol::{SyncRequest, SyncResponse};

/// Combined libp2p behavior for Chains nodes.
#[derive(NetworkBehaviour)]
pub struct ChainsBehaviour {
    /// Peer discovery and content routing.
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// Real-time epidemic broadcast.
    pub gossipsub: gossipsub::Behaviour,
    /// Local network discovery.
    pub mdns: mdns::tokio::Behaviour,
    /// Peer information exchange.
    pub identify: identify::Behaviour,
    /// Historical data synchronization.
    pub sync: request_response::cbor::Behaviour<SyncRequest, SyncResponse>,
}
