pub mod protocol;
pub mod behavior;

pub use protocol::{GossipMessage, SyncRequest, SyncResponse};
pub use behavior::{ChainsBehaviour, ChainsBehaviourEvent};

mod network_impl;
pub use network_impl::Network;