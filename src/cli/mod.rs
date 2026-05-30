use clap::Parser;
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::storage::Storage;
use crate::models::{ChainsResult, Header, Body};
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
    let mut network = Network::new(Arc::clone(&storage), data_dir).await?;
    network.bootstrap_kademlia();

    if let Some(cid_hex) = chain_id_opt {
        let cid = parse_id(&cid_hex)?;
        network.subscribe(&cid)?;
        network.advertise_on_dht(&cid);
    }

    if no_repl {
        loop {
            tokio::select! {
                event = network.swarm.select_next_some() => network.handle_event(event).await?,
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
                        let parts: Vec<&str> = input.split_whitespace().collect();
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
