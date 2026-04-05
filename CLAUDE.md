# Project: Shared Storage Groups on S5 + Sia

## Goal

Build a group storage system where friends can pool Sia-rented storage without any single point of failure. Users join/leave freely via invite links. Files are stored on each user's own Sia backend and can be pinned/replicated to other users' storage for redundancy.

## Core Requirements

- **No SPOF**: No single admin, no central server. Every user runs their own S5 node.
- **Content-addressed sharing**: Files and directories are referenced by BLAKE3 hash. Same content = same hash regardless of filename or location in a user's namespace.
- **Recursive directory sharing**: Sharing a directory hash shares the entire tree. Users mount shared directories wherever they want in their own FS5 namespace.
- **Per-user storage**: Each user's files live on their own Sia contracts (paid with SC). Users choose how much storage to rent each month independently.
- **Pinning/replication**: If User A shares a file, it's a SPOF on A's storage unless User B explicitly pins it to their own Sia backend. Pinning should be a first-class operation. No auto-pinning — FUSE mount fetches on-demand into memory only.
- **Invite links**: A shareable link/token that lets someone join a group and access shared content. Links can be read-only (containing only read capabilities).
- **Elastic**: Users join and leave as they want. No hardware commitment — just Sia rental costs.

## User Workflow

### Sharing files with a group
1. `s5 import local /path/to/dir` — imports files into FS5 + blob store
2. `s5 snapshots create-fs` — snapshots the current FS5 state → hash
3. `s5 group share <group> <label> <hash>` — exports DirV1 metadata to network store + publishes hash to group state

Importing more files after step 2 requires re-running steps 2-3 (the old snapshot hash still points to the old tree).

### Accessing shared files
- `s5 group mount <group> <label> <mountpoint>` — FUSE mount, files fetched on-demand from peers (not persisted locally)
- `s5 group pull <group> <label>` — download into local FS5
- `s5 group pin <group> <label>` — download blobs to local store so this node can serve them to others

### Replicating for redundancy
Join the group and pin:
```
s5 group join <invite_token> --my-name "backup1"
s5 group pin <group> <label>
```
With `peer_default` configured, this node now serves those blobs to anyone who mounts the share.

## What Has Been Built

### 1. `s5_groups` crate (new, in workspace)
Location: `s5_groups/`

**Types** (`types.rs`):
- `GroupId = [u8; 32]`, `MemberId = [u8; 32]`
- `GroupState { name, members: BTreeMap<MemberId, MemberInfo>, shared_roots: BTreeMap<String, SharedRoot> }`
- `MemberInfo { name: String, can_write: bool }`
- `SharedRoot { hash: [u8; 32], published_by: MemberId, description: Option<String> }`
- All types use minicbor Encode/Decode for CBOR serialization

**State management** (`state.rs`):
- `GroupManager` — reads/writes `GroupState` to S5 registry using Ed25519 keypair
- `create()` — generates random keypair, publishes initial state at revision 0
- `open_rw()` / `open_ro()` — opens existing group (with or without secret key)
- `load_state()` / `publish_state()` — CBOR encode/decode via registry
- Registry signing scheme: `sign(MessageType::Registry + key_type_id + pub_key + revision_be_bytes + 0x21 + hash_bytes)`
- Revision tracking: `self.revision` = next revision to publish at (always `msg.revision + 1`)

**Invites** (`invite.rs`):
- `GroupInvite { group_id, bootstrap_peers_raw, capability }`
- `InviteCapability::ReadOnly` or `ReadWrite { secret_key }`
- Bootstrap peers stored as postcard-serialized `iroh::EndpointAddr` bytes in minicbor ByteVec (bridge between minicbor and serde)
- Serialized as CBOR → base64url for sharing as text tokens

### 2. CLI group commands (`s5_cli/src/cmd/group.rs`)

All commands: `s5 group <subcommand>`

| Command | Description |
|---------|-------------|
| `create <name> --my-name <n>` | Create group, generate keypair, publish initial state |
| `join <invite> --my-name <n>` | Join via invite token, add self to member list |
| `leave <group>` | Remove self from group state |
| `members <group>` | List all members |
| `info <group>` | Show group info and shared roots |
| `share <group> <label> <hash>` | Share a snapshot hash; exports DirV1 metadata to blob store |
| `unshare <group> <label>` | Remove a shared root |
| `pull <group> <label>` | Download shared root into local FS5 directory |
| `invite <group> [--read-only]` | Generate invite token with full EndpointAddr |
| `mount <group> <label> <mountpoint>` | FUSE mount with on-demand blob fetching from peers |
| `pin <group> <label> [--path X]` | Pin files from a share to local storage for serving to others |
| `add-member <group> <eid> <name> [--read-only]` | Register a member (for read-only members who can't self-register) |

**Group data persistence** (alongside node config in `<config_dir>/groups/`):
- `<group_id_hex>.key` — 32-byte secret key (empty for read-only)
- `<group_id_hex>.peers` — postcard-serialized `Vec<EndpointAddr>`
- `<name>.alias` — text file mapping name → group_id hex

**Name aliases**: `resolve_group_id()` — accepts 64-char hex OR name alias for all commands.

**Registry setup**: `open_tee_registry()` creates `TeeRegistry(remote, local)` — reads try remote first (freshest state), writes go to both. Uses `WritePolicy::Any` so writes succeed if at least one peer is reachable.

### 3. Read-only member registration
Read-only members cannot publish group state (no signing key). When a read-only member joins:
- They are NOT added to the published group state (since they can't publish)
- Their endpoint ID is printed so a write-capable member can register them
- A write-capable member runs `s5 group add-member <group> <endpoint-id> <name> --read-only`

### 4. Peer discovery from group state
**Problem**: Nodes only knew about bootstrap peers from the invite token. If the inviter went offline, no other peers were reachable.

**Fix**: After loading group state, member endpoint IDs are used to build `EndpointAddr` values. iroh's DHT/pkarr discovery resolves full addresses. New peers are merged into the stored `.peers` file. All peer-consuming commands (mount, pin, pull, members, info) use the combined peer list.

Key functions in `group.rs`:
- `peers_from_state()` — builds `EndpointAddr` from member IDs
- `update_stored_peers()` — merges newly discovered peers into the local `.peers` file

### 5. Snapshot sharing fix
**Problem**: `snapshots create-fs` stores DirV1 metadata in FS5's internal meta blob store (LocalStore at `<fs_root>/`), but the network-served blob store is separate. Peers couldn't download DirV1 metadata.

**Fix**: `group share` now calls `export_dir_metadata_to_store()` which recursively reads all DirV1 blobs from the meta store and imports them into the first configured network blob store.

### 6. FUSE mount with on-demand fetching
**Command**: `s5 group mount <group> <label> <mountpoint>`

**Flow**:
1. Loads group state, builds combined peer list (bootstrap + state-discovered)
2. Wipes temp dir to ensure fresh state on re-mount
3. Fetches DirV1 metadata tree recursively from peers (`fetch_dir_metadata_recursive`)
4. Merges snapshot into a temp FS5 root at `/tmp/s5-group-mount/<group_id>/<label>/`
5. Builds a `FallbackBlobStore` — wraps multiple `BlobStore` instances, tries each in order:
   - Mount's temp meta store (DirV1 metadata)
   - Node's FS5 meta store
   - Configured local blob stores
   - Remote peers via `RemoteBlobStore` (on-demand)
6. Mounts read-only via `s5_fuse::mount`

**Key design details**:
- `FallbackBlobStore` implements `Store` but internally dispatches to `BlobStore::read_as_bytes(hash, ...)` on each store, so each underlying store uses its own path encoding (base32 for local, base64url for remote).
- Empty responses from any store (including remote) are treated as failures, causing fallthrough to the next store.
- Small files (typically ≤64 bytes) may be stored inline in DirV1 metadata as `IdentityRawBinary` — these are served directly from memory without hitting any blob store.
- No auto-pinning: on-demand reads are not persisted. Use `group pin` to replicate locally.

### 7. Group pin command
**Command**: `s5 group pin <group> <label> [--path <path>] [--store <name>] [--jobs N]`

Downloads file content blobs from peers and stores them locally so this node can serve them to others. Supports pinning a single file, a directory, or the entire shared root. Concurrent downloads via `--jobs` (default 8).

### 8. Default peer policy (`peer_default`)
**Problem**: BlobsServer silently drops requests from peers not in `[peer]` config. Also enforces per-node pin checks which block group sharing.

**Fix** (in `s5_blobs` and `s5_node`):
- Added `skip_pin_check: bool` to `PeerConfigBlobs`
- Added `peer_default: Option<NodeConfigPeer>` to `S5NodeConfig`
- Server inserts `peer_default` as `"*"` wildcard in peer_cfg map
- `BlobsServer::cfg_for()` already had wildcard fallback: tries exact match, then `"*"`
- `handle_download` respects `skip_pin_check` to bypass per-node pin enforcement
- Debug logging in `handle_download` for diagnosing blob serving issues

**Required node config for group sharing (ALL nodes that serve blobs)**:
```toml
[peer_default.blobs]
readable_stores = ["local_only_store"]
skip_pin_check = true
```

## Important Architectural Details

### Two separate blob stores
- **FS5 meta blob store**: LocalStore at `<fs_root>/` — stores DirV1 directory metadata blobs. NOT served over the network.
- **Network blob store**: Configured in `[store]` section of node config (e.g., `local_only_store`). Served to peers by BlobsServer.
- `group share` bridges the gap by copying DirV1 blobs from meta → network store.

### Redb lock conflict
Only one process can open a redb database. The S5 server holds the lock while running. Group commands that need registry access must either:
- Run while the server is stopped (e.g., `group create`, `group share`)
- Use remote registry via TeeRegistry to reach a running server (e.g., `group members`, `group info`)

The `Group` command is handled in its own match arm BEFORE the `_ =>` catch-all in `cmd/mod.rs` to avoid opening FS5 (which also locks redb).

### Multi-node local testing
- Each node needs its own config: `~/.config/s5/nodes/node1.toml`, `node2.toml`
- Each node needs namespaced data paths: `registry_path`, `base_path` under `~/.local/share/s5/<node_name>/`
- `init_config.rs` derives `node_name` from config file stem, namespaces paths under `local_data_dir.join(node_name)`
- FS5 roots at `~/.local/share/s5/roots/<node_name>.fs5`

### EndpointAddr in invites
Invite tokens must contain full `iroh::EndpointAddr` (ID + relay URLs + IPs), not just 32-byte IDs. Stored as postcard-serialized bytes within minicbor CBOR structure.

### Registry inline data limit
Group state is stored as inline CBOR in the registry, which has a 1024-byte limit (`MAX_INLINE_DATA_SIZE`). This constrains how much data can be in `GroupState`. Storing per-member `EndpointAddr` (with relay URLs) was attempted but exceeded the limit. Instead, member IDs (32 bytes each, already the map key) are used for iroh DHT discovery.

### Inline file data in DirV1
Small files may be stored as `IdentityRawBinary` blob locations directly in DirV1 metadata. The FUSE read path checks for this first (fs.rs:479-492) and serves from memory. This is why small files work even when remote blob fetching has issues.

## What Still Needs Work

1. **Web interface**: Show shared content with metadata (pin count per blob, local pinning status, who's online). The user wants this alongside FUSE.

2. **Redundancy coordination**: Track which blobs are pinned by how many members so users can make informed decisions. Could be part of the web interface.

3. **Live updates**: Currently sharing a new snapshot requires re-running `group share`. Could use iroh-gossip or registry watches for push notifications when shared roots update.

4. **Encryption support for shared content**: FS5 supports XChaCha20-Poly1305 but shared content currently assumes unencrypted blobs. Sharing encrypted content would require distributing decryption keys via the invite or group state.

5. **Better error handling**: BlobsServer returns empty responses for many error conditions (blob not found, unauthorized). Could return proper error codes so clients can distinguish "not found" from "not authorized".

6. **Scaling beyond small groups**: Current design works for ~5-20 members. For larger groups (100+):
   - Group state CBOR exceeds the 1024-byte registry inline limit — needs blob-referenced state
   - Every membership change rewrites the entire state — needs delta updates or CRDTs
   - Peer discovery builds EndpointAddr for every member — needs smarter peer selection
   - Single registry entry with one keypair — concurrent writes from different members race (last writer wins)

7. **Auto-pin on read**: FUSE mount currently fetches blobs on-demand into memory without persisting. Could optionally cache/pin blobs as they're read to build up local copies over time.

## Technology Stack

### S5 (s5-rs) — content-addressed storage network
- Repo: https://github.com/s5-dev/s5-rs
- Status: 1.0.0-beta.1. Wire-level protocol types are treated as stable; library APIs may still evolve.
- Written in Rust.
- Key crates:
  - `s5_core` — protocol types: Hash, BlobId, BlobLocation, Store trait, RegistryApi trait
  - `s5_fs` — FS5 filesystem: DirV1 immutable snapshots, directory actors, encryption (XChaCha20-Poly1305)
  - `s5_blobs` — iroh-based blob transport (fetch/serve over network), RemoteBlobStore, MultiFetcher
  - `s5_registry` — iroh-based mutable registry (distributed key-value store), MultiRegistry with WritePolicy
  - `s5_node` — orchestration: wires together storage, networking, filesystem, sync
  - `s5_cli` — CLI: `s5 blobs`, `s5 mount`, `s5 group`, etc.
  - `s5_fuse` — FUSE mounting of FS5
  - `s5_groups` — group model, state management, invites
  - `blob_stores/*` — storage backend implementations: local, s3, sia, memory

### Iroh — peer-to-peer transport (used by S5)
- Handles NAT hole-punching, relay fallback, QUIC connections.
- Nodes identified by ed25519 public keys (EndpointId), not IPs/domains.
- Discovery via DHT (pkarr), relay servers, mDNS for LAN.

### Sia — decentralized storage marketplace
- Users rent storage from anonymous hosts, paid in Siacoin (SC).
- renterd exposes an S3-compatible gateway.
- Built-in erasure coding (configurable, default 10-of-30) and encryption.
- S5 has a native Sia blob store backend via the Store trait.

## Useful Links

- S5 Rust repo: https://github.com/s5-dev/s5-rs
- S5 original (Dart): https://github.com/s5-dev/S5
- S5 docs: https://docs.sfive.net/
- S5 Discord: https://discord.gg/Pdutsp5jqR
- Iroh: https://docs.iroh.computer/
- Iroh gossip: https://github.com/n0-computer/iroh-gossip
- Sia renterd: https://sia.tech/renterd
- Sia Foundation grant for S5: https://forum.sia.tech/t/grant-proposal-s5-network-and-apps/305
