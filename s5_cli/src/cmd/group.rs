use anyhow::{Context, Result, anyhow};
use iroh::{Endpoint, EndpointAddr};
use s5_blobs::Client as BlobsClient;
use s5_core::{BlobStore, BlobsRead, Hash};
use s5_fs::{DirContext, FS5, dir::DirV1};
use s5_groups::{GroupInvite, GroupManager, GroupState, InviteCapability, MemberInfo, SharedRoot};
use s5_node::config::S5NodeConfig;
use s5_store_local::{LocalStore, LocalStoreConfig};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use super::util::{open_store, registry_path};
use crate::GroupCmd;
use crate::helpers::{build_endpoint, parse_hash_hex};

pub async fn run_group(
    cmd: GroupCmd,
    config: &S5NodeConfig,
    node_config_file: &std::path::Path,
    fs_root: &Path,
) -> Result<()> {
    let config_dir = node_config_file.parent();
    let endpoint = build_endpoint(&config.identity, config_dir).await?;
    endpoint.online().await;
    let my_endpoint_id: [u8; 32] = *endpoint.id().as_bytes();

    match cmd {
        GroupCmd::Create { name, my_name } => {
            // Create uses local-only registry (we're the first node)
            let registry = open_local_registry(node_config_file, config)?;

            let mgr = GroupManager::create(
                registry,
                name.clone(),
                my_endpoint_id,
                my_name,
            )
            .await?;

            let group_id_hex = hex::encode(mgr.group_id());
            println!("created group '{}'", name);
            println!("group id: {}", group_id_hex);

            // Save group key with no bootstrap peers (we are the origin)
            save_group_data(node_config_file, mgr.group_id(), mgr.signing_key_bytes(), &[])?;
            save_group_alias(node_config_file, &name, mgr.group_id())?;
        }
        GroupCmd::Join { invite, my_name } => {
            let invite = GroupInvite::from_str(&invite)
                .context("failed to parse invite token")?;

            let group_id_hex = hex::encode(&invite.group_id);
            let bootstrap_peers = invite.bootstrap_peers()
                .context("failed to decode bootstrap peers from invite")?;

            // Build a tee registry: local + remote bootstrap peers.
            // On join we need to read from remote (local is empty) and
            // write to both so the update propagates.
            let registry = open_tee_registry(
                node_config_file,
                config,
                &endpoint,
                &bootstrap_peers,
            )?;

            let mut mgr = match &invite.capability {
                InviteCapability::ReadWrite { secret_key } => {
                    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret_key);
                    save_group_data(
                        node_config_file,
                        &invite.group_id,
                        Some(*secret_key),
                        &bootstrap_peers,
                    )?;
                    GroupManager::open_rw(registry, signing_key).await?
                }
                InviteCapability::ReadOnly => {
                    save_group_data(
                        node_config_file,
                        &invite.group_id,
                        None,
                        &bootstrap_peers,
                    )?;
                    GroupManager::open_ro(registry, invite.group_id).await?
                }
            };

            // Load current state from the network and add ourselves
            let mut state = mgr
                .load_state()
                .await?
                .unwrap_or_else(|| GroupState::new(String::new(), my_endpoint_id, my_name.clone()));

            if !state.is_member(&my_endpoint_id) {
                if mgr.can_write() {
                    state.add_member(
                        my_endpoint_id,
                        MemberInfo {
                            name: my_name,
                            can_write: true,
                        },
                    );
                    mgr.publish_state(&state).await?;
                }
            }

            // Save alias using the group's name
            if !state.name.is_empty() {
                save_group_alias(node_config_file, &state.name, &invite.group_id)?;
            }

            println!("joined group '{}': {}", state.name, group_id_hex);
            if mgr.can_write() {
                println!("access: read-write");
            } else {
                println!("access: read-only");
                println!("endpoint id: {}", hex::encode(my_endpoint_id));
                println!(
                    "note: a write-capable member must run `s5 group add-member` to register you"
                );
            }
        }
        GroupCmd::Leave { group_id } => {
            let group_id = resolve_group_id(node_config_file, &group_id)?;
            let gd = load_group_data(node_config_file, &group_id)?;
            let registry = open_tee_registry(
                node_config_file,
                config,
                &endpoint,
                &gd.bootstrap_peers,
            )?;

            if let Some(sk_bytes) = gd.secret_key {
                let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
                let mut mgr = GroupManager::open_rw(registry, sk).await?;

                if let Some(mut state) = mgr.load_state().await? {
                    state.remove_member(&my_endpoint_id);
                    mgr.publish_state(&state).await?;
                }
            }

            remove_group_data(node_config_file, &gd.group_id)?;
            println!("left group: {}", group_id);
        }
        GroupCmd::Members { group_id } => {
            let group_id = resolve_group_id(node_config_file, &group_id)?;
            let gd = load_group_data(node_config_file, &group_id)?;
            let registry = open_tee_registry(
                node_config_file,
                config,
                &endpoint,
                &gd.bootstrap_peers,
            )?;

            let mut mgr = open_manager(registry, &gd.group_id, gd.secret_key).await?;
            let state = mgr
                .load_state()
                .await?
                .ok_or_else(|| anyhow!("group not found in registry"))?;

            println!("group '{}' — {} members:", state.name, state.members.len());
            for (id, info) in &state.members {
                let access = if info.can_write { "rw" } else { "ro" };
                let marker = if *id == my_endpoint_id { " (you)" } else { "" };
                println!("  {} [{}] {}{}", hex::encode(id), access, info.name, marker);
            }
        }
        GroupCmd::Info { group_id } => {
            let group_id = resolve_group_id(node_config_file, &group_id)?;
            let gd = load_group_data(node_config_file, &group_id)?;
            let registry = open_tee_registry(
                node_config_file,
                config,
                &endpoint,
                &gd.bootstrap_peers,
            )?;

            let mut mgr = open_manager(registry, &gd.group_id, gd.secret_key).await?;
            let state = mgr
                .load_state()
                .await?
                .ok_or_else(|| anyhow!("group not found in registry"))?;

            println!("group: {}", state.name);
            println!("id:    {}", group_id);
            println!(
                "access: {}",
                if mgr.can_write() {
                    "read-write"
                } else {
                    "read-only"
                }
            );
            println!("members: {}", state.members.len());
            println!("shared roots: {}", state.shared_roots.len());
            for (label, root) in &state.shared_roots {
                let desc = root.description.as_deref().unwrap_or("");
                println!("  {} — hash={} {}", label, hex::encode(&root.hash), desc);
            }
        }
        GroupCmd::Share {
            group_id,
            label,
            hash,
            description,
        } => {
            let group_id = resolve_group_id(node_config_file, &group_id)?;
            let gd = load_group_data(node_config_file, &group_id)?;
            let registry = open_tee_registry(
                node_config_file,
                config,
                &endpoint,
                &gd.bootstrap_peers,
            )?;
            let hash_parsed = parse_hash_hex(&hash)?;
            let hash_bytes: [u8; 32] = *hash_parsed.as_bytes();

            // Export DirV1 metadata blobs from the FS5 meta store into the
            // network-served blob store so peers can fetch them.
            let network_store = open_first_store(config).await?;
            let meta_store = BlobStore::new(LocalStore::create(LocalStoreConfig {
                base_path: fs_root.to_string_lossy().into(),
            }));
            let count = export_dir_metadata_to_store(
                &meta_store,
                &network_store,
                hash_parsed,
            )
            .await?;
            println!("exported {} metadata blob(s) to network store", count);

            let sk_bytes = gd.secret_key.ok_or_else(|| anyhow!("read-only access, cannot share"))?;
            let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
            let mut mgr = GroupManager::open_rw(registry, sk).await?;

            let mut state = mgr
                .load_state()
                .await?
                .ok_or_else(|| anyhow!("group not found in registry"))?;

            state.share_root(
                label.clone(),
                SharedRoot {
                    hash: hash_bytes,
                    published_by: my_endpoint_id,
                    description,
                },
            );

            mgr.publish_state(&state).await?;
            println!("shared '{}' with group {}", label, group_id);
        }
        GroupCmd::AddMember {
            group_id,
            endpoint_id,
            name,
            read_only,
        } => {
            let group_id = resolve_group_id(node_config_file, &group_id)?;
            let gd = load_group_data(node_config_file, &group_id)?;
            let registry = open_tee_registry(
                node_config_file,
                config,
                &endpoint,
                &gd.bootstrap_peers,
            )?;

            let sk_bytes =
                gd.secret_key.ok_or_else(|| anyhow!("read-only access, cannot add members"))?;
            let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
            let mut mgr = GroupManager::open_rw(registry, sk).await?;

            let mut state = mgr
                .load_state()
                .await?
                .ok_or_else(|| anyhow!("group not found in registry"))?;

            let member_id_bytes: [u8; 32] = hex::decode(&endpoint_id)
                .context("invalid endpoint ID hex")?
                .try_into()
                .map_err(|_| anyhow!("endpoint ID must be 64 hex chars (32 bytes)"))?;

            if state.is_member(&member_id_bytes) {
                println!("member {} is already in the group", endpoint_id);
            } else {
                state.add_member(
                    member_id_bytes,
                    MemberInfo {
                        name: name.clone(),
                        can_write: !read_only,
                    },
                );
                mgr.publish_state(&state).await?;
                let access = if read_only { "ro" } else { "rw" };
                println!("added '{}' [{}] to group", name, access);
            }
        }
        GroupCmd::Unshare { group_id, label } => {
            let group_id = resolve_group_id(node_config_file, &group_id)?;
            let gd = load_group_data(node_config_file, &group_id)?;
            let registry = open_tee_registry(
                node_config_file,
                config,
                &endpoint,
                &gd.bootstrap_peers,
            )?;

            let sk_bytes =
                gd.secret_key.ok_or_else(|| anyhow!("read-only access, cannot unshare"))?;
            let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
            let mut mgr = GroupManager::open_rw(registry, sk).await?;

            let mut state = mgr
                .load_state()
                .await?
                .ok_or_else(|| anyhow!("group not found in registry"))?;

            if state.unshare_root(&label).is_some() {
                mgr.publish_state(&state).await?;
                println!("unshared '{}' from group {}", label, group_id);
            } else {
                println!("label '{}' not found in group", label);
            }
        }
        GroupCmd::Pull {
            group_id,
            label,
            out,
        } => {
            let group_id = resolve_group_id(node_config_file, &group_id)?;
            let gd = load_group_data(node_config_file, &group_id)?;
            let registry = open_tee_registry(
                node_config_file,
                config,
                &endpoint,
                &gd.bootstrap_peers,
            )?;

            let mut mgr = open_manager(registry, &gd.group_id, gd.secret_key).await?;
            let state = mgr
                .load_state()
                .await?
                .ok_or_else(|| anyhow!("group not found in registry"))?;

            let root = state
                .shared_roots
                .get(&label)
                .ok_or_else(|| {
                    let available: Vec<&String> = state.shared_roots.keys().collect();
                    anyhow!(
                        "label '{}' not found in group. available: {:?}",
                        label,
                        available
                    )
                })?;

            let hash = Hash::from_bytes(root.hash);
            println!("pulling '{}' (hash: {})", label, hash);

            // Find a bootstrap peer to download from (try each until one works)
            let mut downloaded = None;
            for peer_addr in &gd.bootstrap_peers {
                if peer_addr.id == endpoint.id() {
                    continue;
                }
                println!("trying peer {}...", peer_addr.id.fmt_short());
                let client = BlobsClient::connect(endpoint.clone(), peer_addr.clone());
                match client.blob_download(hash).await {
                    Ok(bytes) => {
                        downloaded = Some(bytes);
                        println!("downloaded {} bytes", downloaded.as_ref().unwrap().len());
                        break;
                    }
                    Err(e) => {
                        println!("  peer failed: {}", e);
                        continue;
                    }
                }
            }

            let bytes = downloaded.ok_or_else(|| {
                anyhow!("could not download snapshot from any bootstrap peer")
            })?;

            // Decode and restore the FS5 directory snapshot
            let snapshot =
                DirV1::from_bytes(&bytes).context("failed to decode directory snapshot")?;

            let out_dir = if out.as_os_str() == "." {
                std::path::PathBuf::from(&label)
            } else {
                out.clone()
            };

            std::fs::create_dir_all(&out_dir)?;
            let ctx = DirContext::open_local_root(&out_dir)?;
            let fs_local = FS5::open(ctx);
            fs_local
                .merge_from_snapshot(snapshot)
                .await
                .context("failed to merge snapshot")?;
            fs_local.save().await?;

            println!("restored '{}' into {}", label, out_dir.display());
        }
        GroupCmd::Invite {
            group_id,
            read_only,
        } => {
            let group_id = resolve_group_id(node_config_file, &group_id)?;
            let gd = load_group_data(node_config_file, &group_id)?;

            // Use our full endpoint address (ID + relay + IPs) so joiners can reach us
            let my_addr = endpoint.addr();

            let mut peers: Vec<EndpointAddr> = gd.bootstrap_peers;
            // Add ourselves if not already present
            if !peers.iter().any(|p| p.id == endpoint.id()) {
                peers.push(my_addr);
            }

            let invite = if read_only {
                GroupInvite::new_ro(gd.group_id, peers)?
            } else {
                let sk_bytes = gd
                    .secret_key
                    .ok_or_else(|| anyhow!("read-only access, cannot create write invite"))?;
                GroupInvite::new_rw(gd.group_id, sk_bytes, peers)?
            };

            let token = invite.to_string()?;
            println!("{}", token);
        }
        GroupCmd::Pin {
            group_id,
            label,
            path,
            store,
            jobs,
        } => {
            let group_id = resolve_group_id(node_config_file, &group_id)?;
            let gd = load_group_data(node_config_file, &group_id)?;
            let registry = open_tee_registry(
                node_config_file,
                config,
                &endpoint,
                &gd.bootstrap_peers,
            )?;

            let mut mgr = open_manager(registry, &gd.group_id, gd.secret_key).await?;
            let state = mgr
                .load_state()
                .await?
                .ok_or_else(|| anyhow!("group not found in registry"))?;

            let root = state
                .shared_roots
                .get(&label)
                .ok_or_else(|| {
                    let available: Vec<&String> = state.shared_roots.keys().collect();
                    anyhow!("label '{}' not found. available: {:?}", label, available)
                })?;

            let root_hash = Hash::from_bytes(root.hash);

            // Determine target store
            let store_name = store.unwrap_or_else(|| {
                config.store.keys().next().cloned().unwrap_or_else(|| "default".to_string())
            });
            let target_store = open_store(config, &store_name).await
                .with_context(|| format!("store '{}' not found in config", store_name))?;

            // Fetch all DirV1 metadata into a temp store so we can navigate the tree
            let tmp_dir = std::env::temp_dir().join("s5-group-pin").join(&group_id);
            std::fs::create_dir_all(&tmp_dir)?;
            let meta_store = BlobStore::new(LocalStore::create(LocalStoreConfig {
                base_path: tmp_dir.to_string_lossy().into(),
            }));
            let local_meta = BlobStore::new(LocalStore::create(LocalStoreConfig {
                base_path: fs_root.to_string_lossy().into(),
            }));

            println!("fetching directory metadata...");
            let mut visited = HashSet::new();
            let mut meta_count = 0;
            fetch_dir_metadata_recursive(
                root_hash,
                &meta_store,
                &local_meta,
                &gd.bootstrap_peers,
                &endpoint,
                &mut visited,
                &mut meta_count,
            )
            .await?;

            // Navigate to the requested path and collect file hashes
            let mut file_hashes: Vec<(String, Hash, u64)> = Vec::new();
            let root_bytes = meta_store.read_as_bytes(root_hash, 0, None).await?;
            let root_dir = DirV1::from_bytes(&root_bytes)
                .context("failed to decode root DirV1")?;

            if let Some(ref path) = path {
                // Try as file first
                let target_dir = navigate_to_parent(&meta_store, &root_dir, path).await?;
                let file_name = path.rsplit('/').next().unwrap_or(path);
                if let Some(fr) = target_dir.files.get(file_name) {
                    file_hashes.push((path.clone(), Hash::from_bytes(fr.hash), fr.size));
                } else if let Some(dr) = target_dir.dirs.get(file_name) {
                    // It's a directory — collect all files recursively
                    let sub_hash = Hash::from_bytes(dr.hash);
                    let sub_bytes = meta_store.read_as_bytes(sub_hash, 0, None).await?;
                    let sub_dir = DirV1::from_bytes(&sub_bytes)?;
                    collect_file_hashes(&meta_store, &sub_dir, path, &mut file_hashes).await?;
                } else {
                    return Err(anyhow!("'{}' not found in shared root", path));
                }
            } else {
                // Pin everything
                collect_file_hashes(&meta_store, &root_dir, "", &mut file_hashes).await?;
            }

            println!("pinning {} file(s) to store '{}'...", file_hashes.len(), store_name);

            // Also export the DirV1 metadata to the target store
            let mut dir_exported = 0;
            let mut dir_visited = HashSet::new();
            export_dir_recursive(&meta_store, &target_store, root_hash, &mut dir_visited, &mut dir_exported).await?;

            // Download and pin file blobs concurrently
            let concurrency = jobs.max(1);
            let my_id = endpoint.id();
            let peers: Vec<EndpointAddr> = gd.bootstrap_peers.iter()
                .filter(|p| p.id != my_id)
                .cloned()
                .collect();

            let pinned = std::sync::atomic::AtomicUsize::new(0);
            let skipped = std::sync::atomic::AtomicUsize::new(0);
            let failed = std::sync::atomic::AtomicUsize::new(0);

            use futures::stream::StreamExt;
            let results: Vec<Result<()>> = futures::stream::iter(file_hashes.iter().map(|(name, hash, _size)| {
                let endpoint = endpoint.clone();
                let target_store = target_store.clone();
                let peers = peers.clone();
                let name = name.clone();
                let hash = *hash;
                let pinned = &pinned;
                let skipped = &skipped;
                let failed = &failed;
                async move {
                    if target_store.contains(hash).await.unwrap_or(false) {
                        skipped.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return Ok(());
                    }

                    for peer_addr in &peers {
                        let client = BlobsClient::connect(endpoint.clone(), peer_addr.clone());
                        match client.blob_download(hash).await {
                            Ok(bytes) if !bytes.is_empty() => {
                                target_store.import_bytes(bytes).await
                                    .with_context(|| format!("failed to store {}", name))?;
                                pinned.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                return Ok(());
                            }
                            _ => continue,
                        }
                    }

                    failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    println!("  warning: could not download {} (hash: {})", name, hash);
                    Ok(())
                }
            }))
            .buffer_unordered(concurrency)
            .collect()
            .await;

            // Propagate any store errors
            for result in results {
                result?;
            }

            let pinned = pinned.load(std::sync::atomic::Ordering::Relaxed);
            let skipped = skipped.load(std::sync::atomic::Ordering::Relaxed);

            // Clean up temp dir
            let _ = std::fs::remove_dir_all(&tmp_dir);

            println!(
                "pinned {} file(s), skipped {} (already local), {} dir metadata blob(s)",
                pinned, skipped, dir_exported
            );
            let total_size: u64 = file_hashes.iter().map(|(_, _, s)| s).sum();
            println!("total content size: {} bytes", total_size);
        }
        GroupCmd::Mount {
            group_id,
            label,
            mount_point,
            allow_root,
            auto_unmount,
        } => {
            let group_id = resolve_group_id(node_config_file, &group_id)?;
            let gd = load_group_data(node_config_file, &group_id)?;
            let registry = open_tee_registry(
                node_config_file,
                config,
                &endpoint,
                &gd.bootstrap_peers,
            )?;

            let mut mgr = open_manager(registry, &gd.group_id, gd.secret_key).await?;
            let state = mgr
                .load_state()
                .await?
                .ok_or_else(|| anyhow!("group not found in registry"))?;

            let root = state
                .shared_roots
                .get(&label)
                .ok_or_else(|| {
                    let available: Vec<&String> = state.shared_roots.keys().collect();
                    anyhow!(
                        "label '{}' not found in group. available: {:?}",
                        label,
                        available
                    )
                })?;

            let hash = Hash::from_bytes(root.hash);
            println!("mounting '{}' (hash: {}) at {}", label, hash, mount_point.display());

            // Create the temp FS5 root for the mount
            let mount_fs_root = std::env::temp_dir()
                .join("s5-group-mount")
                .join(&group_id)
                .join(&label);
            std::fs::create_dir_all(&mount_fs_root)?;

            // Build a source store that can fetch from local + remote peers
            let mount_meta_store = BlobStore::new(LocalStore::create(LocalStoreConfig {
                base_path: mount_fs_root.to_string_lossy().into(),
            }));
            let local_meta_store = BlobStore::new(LocalStore::create(LocalStoreConfig {
                base_path: fs_root.to_string_lossy().into(),
            }));

            // Recursively fetch all DirV1 metadata blobs into the mount's meta store.
            // Try local meta store first, then remote peers.
            println!("fetching directory metadata tree...");
            let mut fetched = 0usize;
            let mut visited = HashSet::new();
            fetch_dir_metadata_recursive(
                hash,
                &mount_meta_store,
                &local_meta_store,
                &gd.bootstrap_peers,
                &endpoint,
                &mut visited,
                &mut fetched,
            )
            .await?;
            println!("fetched {} directory metadata blob(s)", fetched);

            // Now open the FS5 on the temp root and merge the snapshot
            let snapshot_bytes = mount_meta_store
                .read_as_bytes(hash, 0, None)
                .await
                .context("root DirV1 not in mount meta store after fetch")?;
            let snapshot = DirV1::from_bytes(&snapshot_bytes)
                .context("failed to decode directory snapshot")?;

            let ctx = DirContext::open_local_root(&mount_fs_root)?;
            let fs = FS5::open(ctx);
            fs.merge_from_snapshot(snapshot).await?;
            fs.save().await?;

            // Build blob stores: mount meta store + configured local stores + remote peers
            let mut blob_stores: Vec<Arc<BlobStore>> = Vec::new();

            // 1. Mount's own meta store (has the DirV1 metadata we fetched)
            blob_stores.push(Arc::new(mount_meta_store));

            // 2. Node's FS5 meta store (may have blobs from local imports)
            blob_stores.push(Arc::new(local_meta_store));

            // 3. Configured local blob stores (e.g. "local_only_store")
            for (_name, store_cfg) in &config.store {
                if let s5_node::config::NodeConfigStore::Local(cfg) = store_cfg {
                    let store = BlobStore::new(LocalStore::create(LocalStoreConfig {
                        base_path: cfg.base_path.clone(),
                    }));
                    blob_stores.push(Arc::new(store));
                }
            }

            // 4. Remote peers (on-demand fetching)
            for peer_addr in &gd.bootstrap_peers {
                if peer_addr.id == endpoint.id() {
                    continue;
                }
                let client = BlobsClient::connect(endpoint.clone(), peer_addr.clone());
                let remote = s5_blobs::RemoteBlobStore::new(client);
                blob_stores.push(Arc::new(BlobStore::without_outboard(remote)));
            }

            let fallback = FallbackBlobStore::new(blob_stores);
            let store = BlobStore::without_outboard(fallback);

            std::fs::create_dir_all(&mount_point)?;
            println!("FUSE mount ready — files will be fetched on demand from peers");
            println!("press Ctrl+C to unmount");

            s5_fuse::mount(
                &mount_point,
                fs,
                store,
                true, // read_only
                allow_root,
                auto_unmount,
            )
            .await?;
        }
    }

    Ok(())
}

// --- Registry helpers ---

/// Open just the local redb registry.
fn open_local_registry(
    node_config_file: &std::path::Path,
    config: &S5NodeConfig,
) -> Result<Arc<dyn s5_core::RegistryApi + Send + Sync>> {
    let path = registry_path(node_config_file, config);
    std::fs::create_dir_all(&path)?;
    let registry = s5_registry_redb::RedbRegistry::open(&path)?;
    Ok(Arc::new(registry))
}

/// Open a tee registry that reads/writes both local and remote peers.
///
/// - Reads: try remote first (freshest group state), fall back to local
/// - Writes: go to both local and all remotes
///
/// If the local redb cannot be opened (e.g. the node is running and holds
/// the lock), falls back to remote-only. If no bootstrap peers are
/// available, falls back to local-only.
fn open_tee_registry(
    node_config_file: &std::path::Path,
    config: &S5NodeConfig,
    endpoint: &Endpoint,
    bootstrap_peers: &[EndpointAddr],
) -> Result<Arc<dyn s5_core::RegistryApi + Send + Sync>> {
    let local = open_local_registry(node_config_file, config);

    // Connect to all bootstrap peers, skipping ourselves
    let my_id = endpoint.id();
    let mut remotes: Vec<Arc<dyn s5_core::RegistryApi + Send + Sync>> = Vec::new();
    for peer_addr in bootstrap_peers {
        if peer_addr.id == my_id {
            continue;
        }
        let remote = s5_node::RemoteRegistry::connect(
            endpoint.clone(),
            peer_addr.clone(),
        );
        remotes.push(Arc::new(remote));
    }

    let remote: Option<Arc<dyn s5_core::RegistryApi + Send + Sync>> = if remotes.is_empty() {
        None
    } else if remotes.len() == 1 {
        Some(remotes.into_iter().next().unwrap())
    } else {
        Some(Arc::new(s5_node::MultiRegistry::new(remotes)))
    };

    match (local, remote) {
        (Ok(local), Some(remote)) => {
            let tee = s5_node::TeeRegistry::new(remote, local);
            Ok(Arc::new(tee))
        }
        (Ok(local), None) => Ok(local),
        (Err(_), Some(remote)) => {
            tracing::info!("local registry locked, using remote-only for group state");
            Ok(remote)
        }
        (Err(e), None) => Err(e.context(
            "cannot open local registry (is the node running?) and no bootstrap peers available",
        )),
    }
}

async fn open_manager(
    registry: Arc<dyn s5_core::RegistryApi + Send + Sync>,
    group_id: &[u8; 32],
    signing_key: Option<[u8; 32]>,
) -> Result<GroupManager> {
    if let Some(sk_bytes) = signing_key {
        let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
        GroupManager::open_rw(registry, sk).await
    } else {
        GroupManager::open_ro(registry, *group_id).await
    }
}

// --- Group data persistence ---
//
// Stores group credentials and bootstrap peers alongside the node config.
//
// Layout:
//   <config_dir>/groups/<group_id_hex>.key    — 32-byte secret key (or empty for read-only)
//   <config_dir>/groups/<group_id_hex>.peers   — postcard-serialized Vec<EndpointAddr>

struct GroupData {
    group_id: [u8; 32],
    secret_key: Option<[u8; 32]>,
    bootstrap_peers: Vec<EndpointAddr>,
}

fn groups_dir(node_config_file: &std::path::Path) -> std::path::PathBuf {
    let base = node_config_file
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    base.join("groups")
}

/// Resolve a group identifier that may be either a hex ID or a name alias.
fn resolve_group_id(node_config_file: &std::path::Path, id_or_name: &str) -> Result<String> {
    // If it looks like a 64-char hex string, use it directly
    if id_or_name.len() == 64 && hex::decode(id_or_name).is_ok() {
        return Ok(id_or_name.to_string());
    }

    // Otherwise treat it as a name alias
    let dir = groups_dir(node_config_file);
    let alias_path = dir.join(format!("{}.alias", id_or_name));
    let id_hex = std::fs::read_to_string(&alias_path)
        .with_context(|| format!("group '{}' not found — not a valid hex ID or known alias", id_or_name))?;
    Ok(id_hex.trim().to_string())
}

fn save_group_alias(
    node_config_file: &std::path::Path,
    name: &str,
    group_id: &[u8; 32],
) -> Result<()> {
    let dir = groups_dir(node_config_file);
    std::fs::create_dir_all(&dir)?;
    let alias_path = dir.join(format!("{}.alias", name));
    std::fs::write(&alias_path, hex::encode(group_id)).context("failed to save group alias")?;
    Ok(())
}

fn save_group_data(
    node_config_file: &std::path::Path,
    group_id: &[u8; 32],
    secret_key: Option<[u8; 32]>,
    bootstrap_peers: &[EndpointAddr],
) -> Result<()> {
    let dir = groups_dir(node_config_file);
    std::fs::create_dir_all(&dir)?;
    let id_hex = hex::encode(group_id);

    // Save key
    let key_path = dir.join(format!("{}.key", id_hex));
    let key_data = secret_key.map_or_else(Vec::new, |sk| sk.to_vec());
    std::fs::write(&key_path, &key_data).context("failed to save group key")?;

    // Save peers as postcard
    let peers_path = dir.join(format!("{}.peers", id_hex));
    let peers_data = postcard::to_allocvec(bootstrap_peers)
        .context("failed to serialize bootstrap peers")?;
    std::fs::write(&peers_path, &peers_data).context("failed to save group peers")?;

    Ok(())
}

fn load_group_data(
    node_config_file: &std::path::Path,
    group_id_hex: &str,
) -> Result<GroupData> {
    let group_id = parse_group_id(group_id_hex)?;
    let dir = groups_dir(node_config_file);

    // Load key
    let key_path = dir.join(format!("{}.key", group_id_hex));
    let key_data = std::fs::read(&key_path)
        .with_context(|| format!("group {} not found locally — have you joined it?", group_id_hex))?;

    let secret_key = if key_data.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_data);
        Some(arr)
    } else {
        None
    };

    // Load peers
    let peers_path = dir.join(format!("{}.peers", group_id_hex));
    let bootstrap_peers = if let Ok(peers_data) = std::fs::read(&peers_path) {
        postcard::from_bytes(&peers_data).unwrap_or_default()
    } else {
        Vec::new()
    };

    Ok(GroupData {
        group_id,
        secret_key,
        bootstrap_peers,
    })
}

fn remove_group_data(
    node_config_file: &std::path::Path,
    group_id: &[u8; 32],
) -> Result<()> {
    let dir = groups_dir(node_config_file);
    let id_hex = hex::encode(group_id);
    let key_path = dir.join(format!("{}.key", id_hex));
    let peers_path = dir.join(format!("{}.peers", id_hex));
    if key_path.exists() {
        std::fs::remove_file(&key_path)?;
    }
    if peers_path.exists() {
        std::fs::remove_file(&peers_path)?;
    }
    Ok(())
}

/// Open the first configured blob store (used as the network-served store).
async fn open_first_store(config: &S5NodeConfig) -> Result<BlobStore> {
    let store_name = config
        .store
        .keys()
        .next()
        .ok_or_else(|| anyhow!("no blob stores configured in node config"))?
        .clone();
    open_store(config, &store_name).await
}

/// Recursively copy DirV1 metadata blobs from the FS5 meta store into
/// the network-served blob store. Returns the number of blobs exported.
async fn export_dir_metadata_to_store(
    meta_store: &BlobStore,
    network_store: &BlobStore,
    hash: Hash,
) -> Result<usize> {
    let mut visited = HashSet::new();
    let mut count = 0;
    export_dir_recursive(meta_store, network_store, hash, &mut visited, &mut count).await?;
    Ok(count)
}

async fn export_dir_recursive(
    meta_store: &BlobStore,
    network_store: &BlobStore,
    hash: Hash,
    visited: &mut HashSet<[u8; 32]>,
    count: &mut usize,
) -> Result<()> {
    if !visited.insert(*hash.as_bytes()) {
        return Ok(());
    }

    // Read the DirV1 blob from the FS5 meta store
    let bytes = meta_store
        .read_as_bytes(hash, 0, None)
        .await
        .with_context(|| format!("DirV1 blob {} not found in FS5 meta store", hash))?;

    // Import into network store if not already present
    if !network_store.contains(hash).await? {
        network_store.import_bytes(bytes.clone()).await
            .context("failed to import DirV1 blob into network store")?;
        *count += 1;
    }

    // Parse as DirV1 and recurse into sub-directories
    if let Ok(dir) = DirV1::from_bytes(&bytes) {
        for (_name, dir_ref) in &dir.dirs {
            let sub_hash = Hash::from_bytes(dir_ref.hash);
            Box::pin(export_dir_recursive(
                meta_store,
                network_store,
                sub_hash,
                visited,
                count,
            ))
            .await?;
        }
    }

    Ok(())
}

/// Navigate through DirV1 tree to find the parent directory of a given path.
/// For "a/b/c", returns the DirV1 for "a/b". For "file.txt", returns the root dir.
async fn navigate_to_parent(
    meta_store: &BlobStore,
    root: &DirV1,
    path: &str,
) -> Result<DirV1> {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() <= 1 {
        return Ok(root.clone());
    }

    let mut current = root.clone();
    // Navigate to parent (all parts except the last)
    for part in &parts[..parts.len() - 1] {
        let dir_ref = current.dirs.get(*part)
            .ok_or_else(|| anyhow!("directory '{}' not found", part))?;
        let hash = Hash::from_bytes(dir_ref.hash);
        let bytes = meta_store.read_as_bytes(hash, 0, None).await
            .with_context(|| format!("could not read DirV1 for '{}'", part))?;
        current = DirV1::from_bytes(&bytes)
            .with_context(|| format!("failed to decode DirV1 for '{}'", part))?;
    }
    Ok(current)
}

/// Recursively collect all file hashes from a DirV1 tree.
async fn collect_file_hashes(
    meta_store: &BlobStore,
    dir: &DirV1,
    prefix: &str,
    out: &mut Vec<(String, Hash, u64)>,
) -> Result<()> {
    for (name, fr) in &dir.files {
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", prefix, name)
        };
        out.push((path, Hash::from_bytes(fr.hash), fr.size));
    }

    for (name, dr) in &dir.dirs {
        let sub_path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", prefix, name)
        };
        let sub_hash = Hash::from_bytes(dr.hash);
        if let Ok(bytes) = meta_store.read_as_bytes(sub_hash, 0, None).await {
            if let Ok(sub_dir) = DirV1::from_bytes(&bytes) {
                Box::pin(collect_file_hashes(meta_store, &sub_dir, &sub_path, out)).await?;
            }
        }
    }

    Ok(())
}

/// Recursively fetch DirV1 metadata blobs from local or remote sources into the
/// mount's meta store. Tries the local meta store first, then each bootstrap peer.
async fn fetch_dir_metadata_recursive(
    hash: Hash,
    dest: &BlobStore,
    local_source: &BlobStore,
    bootstrap_peers: &[EndpointAddr],
    endpoint: &iroh::Endpoint,
    visited: &mut HashSet<[u8; 32]>,
    count: &mut usize,
) -> Result<()> {
    if !visited.insert(*hash.as_bytes()) {
        return Ok(());
    }

    // Skip if already in dest
    if dest.contains(hash).await.unwrap_or(false) {
        // Still recurse to check sub-dirs
        let bytes = dest.read_as_bytes(hash, 0, None).await?;
        if let Ok(dir) = DirV1::from_bytes(&bytes) {
            for (_name, dir_ref) in &dir.dirs {
                let sub = Hash::from_bytes(dir_ref.hash);
                Box::pin(fetch_dir_metadata_recursive(
                    sub, dest, local_source, bootstrap_peers, endpoint, visited, count,
                ))
                .await?;
            }
        }
        return Ok(());
    }

    // Try local meta store first
    let bytes = if let Ok(b) = local_source.read_as_bytes(hash, 0, None).await {
        Some(b)
    } else {
        // Try remote peers
        let mut result = None;
        for peer_addr in bootstrap_peers {
            if peer_addr.id == endpoint.id() {
                continue;
            }
            let client = BlobsClient::connect(endpoint.clone(), peer_addr.clone());
            match client.blob_download(hash).await {
                Ok(b) if !b.is_empty() => {
                    result = Some(b);
                    break;
                }
                _ => continue,
            }
        }
        result
    };

    let bytes = bytes.ok_or_else(|| {
        anyhow!("could not fetch DirV1 blob {} from any source", hash)
    })?;

    // Import into dest store
    dest.import_bytes(bytes.clone()).await?;
    *count += 1;

    // Recurse into sub-directories
    if let Ok(dir) = DirV1::from_bytes(&bytes) {
        for (_name, dir_ref) in &dir.dirs {
            let sub = Hash::from_bytes(dir_ref.hash);
            Box::pin(fetch_dir_metadata_recursive(
                sub, dest, local_source, bootstrap_peers, endpoint, visited, count,
            ))
            .await?;
        }
    }

    Ok(())
}

// --- FallbackBlobStore: tries multiple BlobStores in order ---

/// A `Store` that wraps multiple `BlobStore` instances and tries each in order.
/// Each underlying BlobStore uses its own path format (base32 for local, base64url
/// for remote), so hash-to-path conversion is done per-store rather than once.
///
/// Used for FUSE mounts to fetch blobs on demand from local + remote sources.
#[derive(Debug, Clone)]
struct FallbackBlobStore {
    stores: Vec<Arc<BlobStore>>,
}

impl FallbackBlobStore {
    fn new(stores: Vec<Arc<BlobStore>>) -> Self {
        Self { stores }
    }
}

#[async_trait::async_trait]
impl s5_core::store::Store for FallbackBlobStore {
    fn features(&self) -> s5_core::store::StoreFeatures {
        // Use the first store's features as the canonical format.
        // This only matters for paths computed *externally* via BlobStore —
        // our internal methods bypass external path computation by using
        // each store's own blob_path_for_hash.
        if !self.stores.is_empty() {
            s5_core::store::StoreFeatures {
                case_sensitive: false,
                recommended_max_dir_size: 1024,
                supports_rename: false,
            }
        } else {
            s5_core::store::StoreFeatures {
                case_sensitive: false,
                recommended_max_dir_size: 1024,
                supports_rename: false,
            }
        }
    }

    async fn exists(&self, _path: &str) -> s5_core::store::StoreResult<bool> {
        // This is called with a path computed from our features().
        // We can't reliably map it to each store's format, so try to
        // extract the hash and use each store's contains().
        Ok(false)
    }

    async fn open_read_bytes(
        &self,
        path: &str,
        offset: u64,
        max_len: Option<u64>,
    ) -> s5_core::store::StoreResult<bytes::Bytes> {
        // The path was computed using OUR features (base32). We need to
        // try each store using ITS OWN path format. Extract the hash
        // from the path and re-compute per store.
        let hash = extract_hash_from_blob_path(path)?;
        let mut last_err = None;
        for store in &self.stores {
            match store.read_as_bytes(hash, offset, max_len).await {
                Ok(bytes) => return Ok(bytes),
                Err(e) => {
                    tracing::debug!("FallbackBlobStore: read {} failed: {}", hash, e);
                    last_err = Some(e);
                }
            }
        }
        let err = last_err.unwrap_or_else(|| anyhow!("no stores configured"));
        tracing::warn!("FallbackBlobStore: all stores failed for {}: {}", hash, err);
        Err(err)
    }

    async fn open_read_stream(
        &self,
        path: &str,
        _offset: u64,
        _max_len: Option<u64>,
    ) -> s5_core::store::StoreResult<
        Box<dyn futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send + Unpin + 'static>,
    > {
        let hash = extract_hash_from_blob_path(path)?;
        let mut last_err = None;
        for store in &self.stores {
            match store.read_stream(hash).await {
                Ok(reader) => {
                    let stream = tokio_util::io::ReaderStream::new(reader);
                    return Ok(Box::new(stream));
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no stores configured")))
    }

    async fn size(&self, path: &str) -> s5_core::store::StoreResult<u64> {
        let hash = extract_hash_from_blob_path(path)?;
        let mut last_err = None;
        for store in &self.stores {
            match store.size(hash).await {
                Ok(s) => return Ok(s),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no stores configured")))
    }

    async fn put_bytes(&self, _path: &str, _bytes: bytes::Bytes) -> s5_core::store::StoreResult<()> {
        Err(anyhow!("read-only fallback store"))
    }

    async fn put_stream(
        &self,
        _path: &str,
        _stream: Box<dyn futures::Stream<Item = Result<bytes::Bytes, std::io::Error>> + Send + Unpin + 'static>,
    ) -> s5_core::store::StoreResult<()> {
        Err(anyhow!("read-only fallback store"))
    }

    async fn delete(&self, _path: &str) -> s5_core::store::StoreResult<()> {
        Err(anyhow!("read-only fallback store"))
    }

    async fn rename(&self, _old: &str, _new: &str) -> s5_core::store::StoreResult<()> {
        Err(anyhow!("read-only fallback store"))
    }

    async fn provide(
        &self,
        _path: &str,
    ) -> s5_core::store::StoreResult<Vec<s5_core::blob::location::BlobLocation>> {
        Ok(vec![])
    }

    async fn list(
        &self,
    ) -> s5_core::store::StoreResult<
        Box<dyn futures::Stream<Item = Result<String, std::io::Error>> + Send + Unpin + 'static>,
    > {
        Err(anyhow!("list not supported on fallback store"))
    }
}

/// Extract a BLAKE3 hash from a blob path encoded with our features (case-insensitive/base32).
fn extract_hash_from_blob_path(path: &str) -> Result<Hash> {
    let features = s5_core::store::StoreFeatures {
        case_sensitive: false,
        recommended_max_dir_size: 1024,
        supports_rename: false,
    };
    s5_core::BlobStore::hash_from_blob_path(path, &features)
        .map_err(|e| anyhow!("failed to parse blob path: {}", e))?
        .ok_or_else(|| anyhow!("could not extract hash from blob path: {}", path))
}

fn parse_group_id(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).context("invalid hex for group ID")?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "group ID must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}
