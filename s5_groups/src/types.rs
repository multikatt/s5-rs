//! Core group types.

use minicbor::{Decode, Encode};
use std::collections::BTreeMap;

/// A group is identified by its Ed25519 public key (32 bytes).
pub type GroupId = [u8; 32];

/// The full state of a group, stored as a single CBOR blob in the registry.
///
/// This is intentionally kept small (under 1024 bytes for the registry's inline
/// data limit). For groups with many members or shared roots, the state blob
/// will be stored as a regular blob and referenced by hash in the registry entry.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct GroupState {
    /// Human-readable group name.
    #[n(0)]
    pub name: String,

    /// Members keyed by their node's endpoint ID (32 bytes).
    /// Using BTreeMap for deterministic serialization.
    #[n(1)]
    pub members: BTreeMap<MemberId, MemberInfo>,

    /// Content roots shared with the group.
    /// Keyed by a user-chosen label (e.g. "photos", "music").
    #[n(2)]
    pub shared_roots: BTreeMap<String, SharedRoot>,
}

/// A member's iroh endpoint ID (ed25519 public key, 32 bytes).
pub type MemberId = [u8; 32];

/// Information about a group member.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct MemberInfo {
    /// Human-readable display name for this member.
    #[n(0)]
    pub name: String,

    /// Whether this member has write access to the group state.
    /// Read-only members can fetch shared content but cannot modify
    /// the group's membership or shared roots.
    #[n(1)]
    pub can_write: bool,
}

/// A shared content root — a pointer to an immutable FS5 directory snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SharedRoot {
    /// BLAKE3 hash of the directory snapshot blob.
    #[n(0)]
    pub hash: [u8; 32],

    /// Which member published this root (their endpoint ID).
    #[n(1)]
    pub published_by: MemberId,

    /// Optional human-readable description.
    #[n(2)]
    pub description: Option<String>,
}

impl GroupState {
    /// Create a new group with the given name and founding member.
    pub fn new(name: String, founder_id: MemberId, founder_name: String) -> Self {
        let mut members = BTreeMap::new();
        members.insert(
            founder_id,
            MemberInfo {
                name: founder_name,
                can_write: true,
            },
        );

        Self {
            name,
            members,
            shared_roots: BTreeMap::new(),
        }
    }

    /// Add a member to the group.
    pub fn add_member(&mut self, id: MemberId, info: MemberInfo) {
        self.members.insert(id, info);
    }

    /// Remove a member from the group.
    pub fn remove_member(&mut self, id: &MemberId) -> Option<MemberInfo> {
        self.members.remove(id)
    }

    /// Check if a given endpoint ID is a member.
    pub fn is_member(&self, id: &MemberId) -> bool {
        self.members.contains_key(id)
    }

    /// Share a content root with the group.
    pub fn share_root(&mut self, label: String, root: SharedRoot) {
        self.shared_roots.insert(label, root);
    }

    /// Remove a shared root.
    pub fn unshare_root(&mut self, label: &str) -> Option<SharedRoot> {
        self.shared_roots.remove(label)
    }
}
