use clap::Parser;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::storage::Storage;
use crate::models::ChainsResult;
use crate::crypto::keys::generate_signing_key;
use crate::cli::args::{Cli, Commands};
use crate::cli::handlers::CommandHandlers;
use ed25519_dalek::SigningKey;
use rand::random;
use std::fs;

pub mod args;
pub mod handlers;

/// Entry point for the CLI application.
pub async fn run() -> ChainsResult<()> {
    let cli = Cli::parse();
    let signing_key = load_or_generate_identity()?;

    match cli.command {
        Commands::Daemon { chain_id, data_dir, no_repl, key } => {
            let storage = Arc::new(Mutex::new(Storage::new(&data_dir)?));
            let enc_key = parse_key_opt(key.as_deref())?;
            run_daemon(storage, signing_key, chain_id, &data_dir, no_repl, enc_key).await?;
        }
        _ => {
            let storage = Arc::new(Mutex::new(Storage::new("./chains.db")?));
            match cli.command {
                Commands::Create { .. } => {
                    let id: [u8; 32] = random();
                    storage.lock().await.create_chain(&id)?;
                    println!("Created chain: {}", hex::encode(id));
                }
                Commands::Append { chain_id, data, ttl, key } => {
                    let id = parse_id(&chain_id)?;
                    let enc_key = parse_key_opt(key.as_deref())?;
                    CommandHandlers::append_local(&storage, &signing_key, id, &data, ttl, enc_key.as_ref()).await?;
                }
                Commands::List => {
                    let chains = storage.lock().await.list_chains()?;
                    for id in chains {
                        let latest = storage.lock().await.get_latest_sequence(&id)?;
                        println!("{} ({} blocks)", hex::encode(id), latest);
                    }
                }
                Commands::Show { chain_id, key } => {
                    let id = parse_id(&chain_id)?;
                    let enc_key = parse_key_opt(key.as_deref())?;
                    CommandHandlers::show_chain(&storage, id, enc_key.as_ref()).await?;
                }
                Commands::Verify { chain_id } => {
                    let id = parse_id(&chain_id)?;
                    if let Some(chain) = storage.lock().await.get_chain(&id)? {
                        chain.validate()?;
                        println!("Chain is VALID");
                    }
                }
                Commands::EpochRotate { chain_id } => {
                    let id = parse_id(&chain_id)?;
                    let storage = storage.lock().await;
                    if !storage.chain_exists(&id)? {
                        return Err("Chain not found.".into());
                    }
                    use crate::crypto::epoch::EpochManager;
                    let mut manager = EpochManager::new();
                    let new_key = manager.rotate();
                    let epoch = manager.current_epoch();
                    storage.store_epoch_key(&id, epoch, &new_key)?;
                    println!("Rotated to epoch {} key: {}", epoch, hex::encode(new_key));
                }
                Commands::Gc { chain_id } => {
                    let id = parse_id(&chain_id)?;
                    let storage = storage.lock().await;
                    if !storage.chain_exists(&id)? {
                        return Err("Chain not found.".into());
                    }
                    let stats = storage.collect_garbage(&id)?;
                    println!("GC complete: {} bodies pruned, {} headers pruned, {} snapshots created, {} bytes freed",
                        stats.bodies_pruned, stats.headers_pruned, stats.snapshots_created, stats.bytes_freed);
                }
                Commands::RatchetInit { chain_id, remote_key } => {
                    let id = parse_id(&chain_id)?;
                    let storage = storage.lock().await;
                    if !storage.chain_exists(&id)? {
                        return Err("Chain not found.".into());
                    }
                    use crate::crypto::ratchet::{RatchetState, generate_dh_keypair};
                    let (sk, pk) = generate_dh_keypair();
                    let root_key: [u8; 32] = rand::random();
                    let session = if let Some(rk_hex) = remote_key {
                        let rk = parse_id(&rk_hex)?;
                        RatchetState::new_receiver(root_key, sk, pk, rk)
                    } else {
                        RatchetState::new_sender(root_key, sk, pk)
                    };
                    storage.store_ratchet_session(&id, &session)?;
                    println!("Ratchet session initialized for chain {} with pubkey: {}", hex::encode(id), hex::encode(pk));
                }
                _ => unreachable!(),
            }
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
    mut enc_key: Option<[u8; 32]>,
) -> ChainsResult<()> {
    use crate::network::Network;
    use futures::StreamExt;
    use tokio::io::{AsyncBufReadExt, BufReader};

    println!("[daemon] starting...");
    let mut network: Network = Network::new(Arc::clone(&storage), data_dir).await?;
    network.bootstrap_kademlia();

    if let Some(ref cid_hex) = chain_id_opt {
        let cid = parse_id(cid_hex)?;
        network.subscribe(&cid)?;
        network.advertise_on_dht(&cid);
    }

    if no_repl {
        let mut gc_interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                event = network.swarm.select_next_some() => network.handle_event(event).await?,
                _ = gc_interval.tick() => {
                    if let Some(ref cid) = chain_id_opt {
                        if let Ok(id) = parse_id(cid) {
                            let storage = storage.lock().await;
                            let _stats = storage.collect_garbage(&id);
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => break,
            }
        }
    } else {
        let mut stdin = BufReader::new(tokio::io::stdin()).lines();
        loop {
            tokio::select! {
                event = network.swarm.select_next_some() => network.handle_event(event).await?,
                line = stdin.next_line() => {
                    if let Ok(Some(input)) = line {
                        let parts: Vec<&str> = input.split_whitespace().collect::<Vec<&str>>();
                        if parts.is_empty() { continue; }
                        match parts[0] {
                            "append" if parts.len() >= 3 => {
                                let id = parse_id(parts[1])?;
                                let data = parts[2..].join(" ");
                                CommandHandlers::append_local(&storage, &signing_key, id, &data, 0, enc_key.as_ref()).await?;
                                let latest = storage.lock().await.get_latest_sequence(&id)?;
                                if let Some(h) = storage.lock().await.get_header(&id, latest)? {
                                    if let Some(b) = storage.lock().await.get_body(&h.block_id)? {
                                        network.publish_block(&h, &b)?;
                                    }
                                }
                            }
                            "set-key" if parts.len() >= 2 => {
                                enc_key = parse_key_opt(Some(parts[1]))?;
                                println!("Key set.");
                            }
                            "gc" if parts.len() >= 2 => {
                                let id = parse_id(parts[1])?;
                                let storage = storage.lock().await;
                                let stats = storage.collect_garbage(&id)?;
                                println!("GC: {} bodies, {} headers pruned, {} snapshots",
                                    stats.bodies_pruned, stats.headers_pruned, stats.snapshots_created);
                            }
                            "epoch-rotate" if parts.len() >= 2 => {
                                let id = parse_id(parts[1])?;
                                let storage = storage.lock().await;
                                use crate::crypto::epoch::EpochManager;
                                let mut manager = EpochManager::new();
                                let new_key = manager.rotate();
                                let epoch = manager.current_epoch();
                                storage.store_epoch_key(&id, epoch, &new_key)?;
                                println!("Epoch {} key: {}", epoch, hex::encode(new_key));
                            }
                            "exit" => break,
                            _ => println!("Unknown command."),
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => break,
            }
        }
    }
    Ok(())
}

fn parse_id(s: &str) -> ChainsResult<[u8; 32]> {
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 { return Err("Invalid ID length".into()); }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_key_opt(key: Option<&str>) -> ChainsResult<Option<[u8; 32]>> {
    match key {
        Some(k) => {
            let bytes = if k.len() == 64 { hex::decode(k)? } else { k.as_bytes().to_vec() };
            if bytes.len() != 32 { return Err("Key must be 32 bytes".into()); }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Some(arr))
        }
        None => Ok(None),
    }
}

fn load_or_generate_identity() -> ChainsResult<SigningKey> {
    if let Ok(bytes) = fs::read("node.key") {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Ok(SigningKey::from_bytes(&arr));
        }
    }
    let key = generate_signing_key();
    fs::write("node.key", key.to_bytes())?;
    Ok(key)
}
