use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "chains")]
#[command(about = "Chains: decentralized append-only log")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new chain
    Create {
        #[arg(short, long, default_value = "")]
        name: String,
    },
    /// Append data to a chain
    Append {
        chain_id: String,
        data: String,
        #[arg(short, long, default_value_t = 0)]
        ttl: u32,
        #[arg(short, long)]
        key: Option<String>,
    },
    /// List local chains
    List,
    /// Show chain contents
    Show {
        chain_id: String,
        #[arg(short, long)]
        key: Option<String>,
    },
    /// Verify chain integrity
    Verify {
        chain_id: String,
    },
    /// Start P2P daemon with GossipSub + Kademlia DHT
    Daemon {
        #[arg(short, long)]
        chain_id: Option<String>,
        #[arg(short = 'd', long, default_value = "./chains.db")]
        data_dir: String,
        #[arg(long)]
        no_repl: bool,
        #[arg(short, long)]
        key: Option<String>,
    },
    /// Rotate the epoch key for a streaming chain
    EpochRotate {
        chain_id: String,
    },
    /// Run garbage collection (prune expired bodies/snapshots)
    Gc {
        chain_id: String,
    },
    /// Initialize a Double Ratchet session for private messaging
    RatchetInit {
        chain_id: String,
        #[arg(short, long)]
        remote_key: Option<String>,
    },
}
