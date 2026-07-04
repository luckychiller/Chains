pub mod behavior;
pub mod protocol;

pub use behavior::{ChainsBehaviour, ChainsBehaviourEvent};
pub use protocol::{GossipMessage, SyncRequest, SyncResponse};

#[allow(clippy::module_inception)]
mod network;
pub use self::network::Network;
