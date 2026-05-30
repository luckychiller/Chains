use clap::{Parser, Subcommand};
use crate::header::Header;
use crate::body::Body;
use crate::storage::Storage;
use crate::crypto::generate_signing_key;
use crate::network::Network;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::random;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::io::{AsyncBufReadExt, BufReader};
use std::fs;
use ed25519_dalek::SigningKey;
use futures::StreamExt;


#[derive(Parser)]
#[command(name = "chains")]
#[command(about = "Chains: decentralized append-only log")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
}

pub async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    let signing_key = load_or_generate_identity()?;

    match &cli.command {
        Commands::Daemon { chain_id, data_dir, no_repl, key } => {
            let storage = Arc::new(Mutex::new(Storage::new(data_dir)?));
            let encryption_key = parse_key_opt(key.as_deref())?;
            run_daemon(storage, signing_key, chain_id.clone(), data_dir, *no_repl, encryption_key).await
        }
        _ => {
            let storage = Arc::new(Mutex::new(Storage::new("./chains.db")?));
            match &cli.command {
                Commands::Create { name: _ } => {
                    let chain_id: [u8; 32] = random();
                    println!("Created chain: {}", hex::encode(chain_id));
                    let storage = storage.lock().await;
                    storage.create_chain(&chain_id)?;
                }
                Commands::Append { chain_id, data, ttl, key } => {
                    let encryption_key = parse_key_opt(key.as_deref())?;
                    append_local(&storage, &signing_key, &chain_id, &data, *ttl, encryption_key.as_ref()).await?;
                }
                Commands::List => {
                    let storage = storage.lock().await;
                    let chains = storage.list_chains()?;
                    if chains.is_empty() {
                        println!("No chains found.");
                    } else {
                        println!("Chains:");
                        for chain_id in chains {
                            let latest = storage.get_latest_sequence(&chain_id)?;
                            println!("  {} ({} blocks)", hex::encode(chain_id), latest);
                        }
                    }
                }
                Commands::Show { chain_id, key } => {
                    let storage = storage.lock().await;
                    let encryption_key = parse_key_opt(key.as_deref())?;
                    show_chain(&storage, &chain_id, encryption_key.as_ref()).await?;
                }
                Commands::Verify { chain_id } => {
                    let storage = storage.lock().await;
                    verify_chain(&storage, &chain_id).await?;
                }
                _ => unreachable!(),
            }
            Ok(())
        }
    }
}

fn parse_key_opt(key: Option<&str>) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error + Send + Sync>> {
    match key {
        Some(k) => {
            let bytes = if k.len() == 64 {
                hex::decode(k).map_err(|e| format!("Invalid hex key: {}", e))?
            } else if k.len() == 32 {
                k.as_bytes().to_vec()
            } else {
                return Err("Encryption key must be 32 bytes (64 hex chars or 32 raw chars)".into());
            };
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

async fn append_local(
    storage: &Arc<Mutex<Storage>>,
    signing_key: &SigningKey,
    chain_id_hex: &str,
    data: &str,
    ttl: u32,
    encryption_key: Option<&[u8; 32]>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let chain_id_bytes = hex::decode(chain_id_hex)
        .map_err(|e| format!("Invalid hex chain ID: {}", e))?;
    if chain_id_bytes.len() != 32 {
        return Err("Chain ID must be 32 bytes (64 hex chars)".into());
    }
    let mut chain_id_arr = [0u8; 32];
    chain_id_arr.copy_from_slice(&chain_id_bytes);

    let storage_lock = storage.lock().await;
    if !storage_lock.chain_exists(&chain_id_arr)? {
        return Err("Chain not found. Create it first with `chains create`.".into());
    }

    let latest_seq = storage_lock.get_latest_sequence(&chain_id_arr)?;
    let sequence = latest_seq + 1;

    let prev_hash = if sequence == 1 {
        [0u8; 32]
    } else {
        let prev = storage_lock
            .get_header(&chain_id_arr, sequence - 1)?
            .ok_or("Previous header not found")?;
        prev.block_id
    };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Time error: {}", e))?
        .as_secs();

    let body = if let Some(key) = encryption_key {
        Body::new_encrypted([0; 32], data.as_bytes(), key)?
    } else {
        Body::new([0; 32], data.as_bytes().to_vec())
    };
    let body_hash = body.body_hash();
    let author_id = signing_key.verifying_key().to_bytes();

    let header = Header::new(
        chain_id_arr,
        author_id,
        sequence,
        timestamp,
        prev_hash,
        body_hash,
        ttl,
        signing_key,
    );

    let mut body = body;
    body.block_id = header.block_id;

    storage_lock.store_header(&chain_id_arr, sequence, &header)?;
    storage_lock.store_body(&body.block_id, &body)?;
    storage_lock.update_latest_sequence(&chain_id_arr, sequence)?;

    println!("Appended block {} to chain {}", sequence, hex::encode(chain_id_arr));
    Ok(())
}

async fn show_chain(
    storage: &tokio::sync::MutexGuard<'_, Storage>,
    chain_id_hex: &str,
    encryption_key: Option<&[u8; 32]>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let chain_id_bytes = hex::decode(chain_id_hex)
        .map_err(|e| format!("Invalid hex chain ID: {}", e))?;
    if chain_id_bytes.len() != 32 {
        return Err("Chain ID must be 32 bytes".into());
    }
    let mut chain_id_arr = [0u8; 32];
    chain_id_arr.copy_from_slice(&chain_id_bytes);

    if !storage.chain_exists(&chain_id_arr)? {
        return Err("Chain not found.".into());
    }

    let latest = storage.get_latest_sequence(&chain_id_arr)?;
    println!("Chain:  {}", hex::encode(chain_id_arr));
    println!("Blocks: {}", latest);
    println!();

    for seq in 1..=latest {
        if let Some(header) = storage.get_header(&chain_id_arr, seq)? {
            let body = storage.get_body(&header.block_id)?;
            let data_str = if let Some(body) = body {
                if body.encryption_algo != "none" {
                    if let Some(key) = encryption_key {
                        match body.decrypt(key) {
                            Ok(plain) => String::from_utf8(plain).unwrap_or_else(|_| "<binary decrypted>".to_string()),
                            Err(e) => format!("<decryption failed: {}>", e),
                        }
                    } else {
                        "<encrypted>".to_string()
                    }
                } else {
                    String::from_utf8(body.ciphertext.clone()).unwrap_or_else(|_| "<binary>".to_string())
                }
            } else {
                "<missing body>".to_string()
            };

            println!(
                "[{}] id={}.. prev={}.. hash={}.. ttl={} data={:?}",
                header.sequence,
                hex::encode(&header.block_id[..4]),
                hex::encode(&header.prev_hash[..4]),
                hex::encode(&header.body_hash[..4]),
                header.ttl,
                if data_str.len() > 80 {
                    format!("{}...", &data_str[..80])
                } else {
                    data_str
                },
            );
        }
    }
    Ok(())
}

async fn verify_chain(
    storage: &tokio::sync::MutexGuard<'_, Storage>,
    chain_id_hex: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let chain_id_bytes = hex::decode(chain_id_hex)
        .map_err(|e| format!("Invalid hex chain ID: {}", e))?;
    if chain_id_bytes.len() != 32 {
        return Err("Chain ID must be 32 bytes".into());
    }
    let mut chain_id_arr = [0u8; 32];
    chain_id_arr.copy_from_slice(&chain_id_bytes);

    let chain = storage.get_chain(&chain_id_arr)?;
    match chain {
        Some(chain) => {
            chain.validate()?;
            println!("Chain {}: VALID ({} blocks)", hex::encode(chain_id_arr), chain.headers.len());
        }
        None => {
            return Err("Chain not found.".into());
        }
    }
    Ok(())
}

async fn run_daemon(
    storage: Arc<Mutex<Storage>>,
    signing_key: SigningKey,
    chain_id_opt: Option<String>,
    data_dir: &str,
    no_repl: bool,
    encryption_key: Option<[u8; 32]>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("[daemon] starting Chains P2P node...");
    let key_dir = std::path::Path::new(data_dir).parent().and_then(|p| p.to_str()).unwrap_or(".");
    let mut network = Network::new(Arc::clone(&storage), key_dir).await?;
    network.bootstrap_kademlia();

    let mut subscribed_cids: Vec<[u8; 32]> = Vec::new();
    let mut current_encryption_key = encryption_key;

    if let Some(ref cid_hex) = chain_id_opt {
        let cid_bytes = hex::decode(cid_hex)
            .map_err(|e| format!("Invalid hex chain ID: {}", e))?;
        if cid_bytes.len() != 32 {
            return Err("Chain ID must be 32 bytes".into());
        }
        let mut cid = [0u8; 32];
        cid.copy_from_slice(&cid_bytes);

        subscribe_to_chain(&mut network, &storage, &cid).await?;
        subscribed_cids.push(cid);
        println!("[daemon] subscribed to chain: {}", hex::encode(cid));
    }

    let peer_id = network.peer_id;
    println!("[daemon] peer ID: {:?}", peer_id);

    if no_repl {
        println!("[daemon] running in headless mode (Ctrl+C to quit)");
        println!();
        loop {
            tokio::select! {
                event = network.swarm.select_next_some() => {
                    if let Err(e) = network.handle_event(event).await {
                        eprintln!("[daemon] event error: {}", e);
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("\n[daemon] shutting down...");
                    break;
                }
            }
        }
    } else {
        println!("[daemon] type 'help' for commands, Ctrl+C to quit");
        println!();

        let mut stdin = BufReader::new(tokio::io::stdin()).lines();

        loop {
            tokio::select! {
                event = network.swarm.select_next_some() => {
                    if let Err(e) = network.handle_event(event).await {
                        eprintln!("[daemon] event error: {}", e);
                    }
                }
                line = stdin.next_line() => {
                    match line {
                        Ok(Some(input)) => {
                            let input = input.trim().to_string();
                            if input.is_empty() {
                                continue;
                            }
                            match process_daemon_command(
                                &mut network, &storage, &signing_key,
                                &input, &mut subscribed_cids, &mut current_encryption_key,
                            ).await {
                                Ok(DaemonAction::Exit) => break,
                                Ok(DaemonAction::Continue) => {}
                                Err(e) => eprintln!("[daemon] error: {}", e),
                            }
                        }
                        Ok(None) => break,
                        Err(e) => eprintln!("[daemon] stdin error: {}", e),
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    println!("\n[daemon] shutting down...");
                    break;
                }
            }
        }
    }
    Ok(())
}

async fn subscribe_to_chain(
    network: &mut Network,
    storage: &Arc<Mutex<Storage>>,
    chain_id: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let storage = storage.lock().await;
    if !storage.chain_exists(chain_id)? {
        storage.create_chain(chain_id)?;
    }
    drop(storage);

    network.subscribe(chain_id)?;
    network.advertise_on_dht(chain_id);
    Ok(())
}

enum DaemonAction {
    Continue,
    Exit,
}

async fn process_daemon_command(
    network: &mut Network,
    storage: &Arc<Mutex<Storage>>,
    signing_key: &SigningKey,
    input: &str,
    subscribed_cids: &mut Vec<[u8; 32]>,
    encryption_key: &mut Option<[u8; 32]>,
) -> Result<DaemonAction, Box<dyn std::error::Error + Send + Sync>> {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(DaemonAction::Continue);
    }

    match parts[0] {
        "help" => {
            println!("Commands:");
            println!("  help                         Show this help");
            println!("  create                       Create a new chain");
            println!("  append <chain_id> <data>     Append block and publish via GossipSub");
            println!("  subscribe <chain_id>         Subscribe to a chain topic");
            println!("  list                         List local chains");
            println!("  show <chain_id>              Show chain contents");
            println!("  verify <chain_id>            Verify chain integrity");
            println!("  peers                        Show peer count");
            println!("  set-key <hex_key>            Set default encryption key");
            println!("  exit                         Shutdown");
        }
        "set-key" => {
            if parts.len() < 2 {
                println!("Usage: set-key <hex_key>");
                return Ok(DaemonAction::Continue);
            }
            *encryption_key = parse_key_opt(Some(parts[1]))?;
            println!("Encryption key updated.");
        }
        "create" => {
            let chain_id: [u8; 32] = random();
            {
                let guard = storage.lock().await;
                guard.create_chain(&chain_id)?;
            }
            println!("Created chain: {}", hex::encode(chain_id));
            subscribe_to_chain(network, storage, &chain_id).await?;
            subscribed_cids.push(chain_id);
            println!("Subscribed to chain: {}", hex::encode(chain_id));
        }
        "append" => {
            if parts.len() < 3 {
                println!("Usage: append <chain_id> <data>");
                return Ok(DaemonAction::Continue);
            }
            let chain_id_hex = parts[1];
            let data = parts[2..].join(" ");
            append_local(storage, signing_key, chain_id_hex, &data, 0, encryption_key.as_ref()).await?;

            let cid_bytes = hex::decode(chain_id_hex)
                .map_err(|e| format!("Invalid hex: {}", e))?;
            let mut cid = [0u8; 32];
            cid.copy_from_slice(&cid_bytes);

            let storage_lock = storage.lock().await;
            if let Some(header) = storage_lock.get_header(&cid, storage_lock.get_latest_sequence(&cid)?)? {
                if let Some(body) = storage_lock.get_body(&header.block_id)? {
                    if let Err(e) = network.publish_block(&header, &body) {
                        eprintln!("[daemon] failed to publish block: {}", e);
                    } else {
                        println!("[daemon] published block {} via GossipSub", header.sequence);
                    }
                }
            }
        }
        "subscribe" => {
            if parts.len() < 2 {
                println!("Usage: subscribe <chain_id>");
                return Ok(DaemonAction::Continue);
            }
            let cid_bytes = hex::decode(parts[1])
                .map_err(|e| format!("Invalid hex: {}", e))?;
            let mut cid = [0u8; 32];
            cid.copy_from_slice(&cid_bytes);

            subscribe_to_chain(network, storage, &cid).await?;
            subscribed_cids.push(cid);
            println!("Subscribed to chain: {}", hex::encode(cid));
        }
        "list" => {
            let storage = storage.lock().await;
            let chains = storage.list_chains()?;
            if chains.is_empty() {
                println!("No chains found.");
            } else {
                println!("Chains:");
                for cid in chains {
                    let _latest = storage.get_latest_sequence(&cid)?;
                    let subscribed = if subscribed_cids.contains(&cid) { " (subscribed)" } else { "" };
                    println!("  {}{}", hex::encode(cid), subscribed);
                }
            }
        }
        "show" => {
            if parts.len() < 2 {
                println!("Usage: show <chain_id>");
                return Ok(DaemonAction::Continue);
            }
            let storage = storage.lock().await;
            show_chain(&storage, parts[1], encryption_key.as_ref()).await?;
        }
        "verify" => {
            if parts.len() < 2 {
                println!("Usage: verify <chain_id>");
                return Ok(DaemonAction::Continue);
            }
            let storage = storage.lock().await;
            verify_chain(&storage, parts[1]).await?;
        }
        "peers" => {
            let n_peers = network.swarm.connected_peers().count();
            println!("Connected peers: {}", n_peers);
            for peer in network.swarm.connected_peers() {
                println!("  {:?}", peer);
            }
        }
        "exit" | "quit" => {
            println!("Shutting down...");
            return Ok(DaemonAction::Exit);
        }
        _ => {
            println!("Unknown command: {}. Type 'help' for available commands.", parts[0]);
        }
    }
    Ok(DaemonAction::Continue)
}

fn load_or_generate_identity() -> Result<SigningKey, Box<dyn std::error::Error + Send + Sync>> {
    let key_path = "node.key";
    if let Ok(bytes) = fs::read(key_path) {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Ok(SigningKey::from_bytes(&arr));
        }
    }
    let key = generate_signing_key();
    fs::write(key_path, key.to_bytes())?;
    Ok(key)
}
