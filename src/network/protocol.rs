use crate::models::{Body, Header};
use serde::{Deserialize, Serialize};

/// Protocol constants.
pub const CHAINS_PROTOCOL: &str = "/chains/0.1.0";
pub const SYNC_PROTOCOL: &str = "/chains/sync/0.1.0";

/// Messages broadcast over GossipSub.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum GossipMessage {
    /// A new block (Header + Body) being pushed to the swarm.
    Block(Header, Body),
}

/// Requests for the Sparse Pull synchronization protocol.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum SyncRequest {
    /// Query a peer for their latest sequence number on a chain.
    GetLatestSequence { chain_id: [u8; 32] },
    /// Request a range of headers.
    GetHeaders {
        chain_id: [u8; 32],
        start_seq: u64,
        end_seq: u64,
    },
    /// Request the body for a specific block.
    GetBody { block_id: [u8; 32] },
}

/// Responses for the Sparse Pull synchronization protocol.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum SyncResponse {
    LatestSequence { chain_id: [u8; 32], sequence: u64 },
    Headers(Vec<Header>),
    Body(Option<Body>),
    Error(String),
}
