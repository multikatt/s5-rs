//! Group shared storage for S5.
//!
//! This crate implements a decentralized group model on top of S5's content-addressed
//! storage and mutable registry. Groups allow friends to pool Sia-rented storage
//! without any single point of failure.
//!
//! # Design
//!
//! A **group** is identified by an Ed25519 keypair. The group's public key serves as
//! the group identity, and the corresponding secret key is shared among members who
//! have write access. Read-only members receive only the public key (plus encryption
//! keys for any encrypted content).
//!
//! Group state is stored as a CBOR-encoded [`GroupState`] blob, published to the S5
//! registry under the group's public key (`StreamKey::PublicKeyEd25519`). This gives
//! us:
//! - **Mutable state**: The registry keeps only the latest revision, so membership
//!   changes and new shared roots overwrite the previous state.
//! - **Authenticated updates**: Only holders of the group secret key can publish
//!   valid updates (Ed25519 signature required).
//! - **P2P propagation**: The registry is gossiped between connected S5 nodes, so
//!   group state updates reach all online members automatically.
//!
//! # Invite links
//!
//! An invite is a compact token containing the group public key, one or more bootstrap
//! peer endpoint IDs, and optionally the group secret key (for write access) or just
//! read capability. Invites are serialized as base64url strings for easy sharing.

pub mod invite;
pub mod state;
pub mod types;

pub use invite::{GroupInvite, InviteCapability};
pub use state::GroupManager;
pub use types::{GroupId, GroupState, MemberInfo, SharedRoot};
