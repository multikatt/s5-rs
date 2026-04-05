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

#[cfg(test)]
mod tests {
    use super::*;

    fn member_id(b: u8) -> MemberId {
        [b; 32]
    }

    fn hash(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn new_group_has_founder_as_write_member() {
        let state = GroupState::new("test".into(), member_id(1), "alice".into());
        assert_eq!(state.name, "test");
        assert_eq!(state.members.len(), 1);
        assert!(state.is_member(&member_id(1)));
        assert!(state.members[&member_id(1)].can_write);
        assert_eq!(state.members[&member_id(1)].name, "alice");
        assert!(state.shared_roots.is_empty());
    }

    #[test]
    fn add_and_remove_member() {
        let mut state = GroupState::new("test".into(), member_id(1), "alice".into());

        state.add_member(
            member_id(2),
            MemberInfo {
                name: "bob".into(),
                can_write: false,
            },
        );
        assert_eq!(state.members.len(), 2);
        assert!(state.is_member(&member_id(2)));
        assert!(!state.members[&member_id(2)].can_write);

        let removed = state.remove_member(&member_id(2));
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "bob");
        assert!(!state.is_member(&member_id(2)));
        assert_eq!(state.members.len(), 1);
    }

    #[test]
    fn remove_nonexistent_member_returns_none() {
        let mut state = GroupState::new("test".into(), member_id(1), "alice".into());
        assert!(state.remove_member(&member_id(99)).is_none());
    }

    #[test]
    fn share_and_unshare_root() {
        let mut state = GroupState::new("test".into(), member_id(1), "alice".into());

        state.share_root(
            "photos".into(),
            SharedRoot {
                hash: hash(0xAA),
                published_by: member_id(1),
                description: Some("vacation pics".into()),
            },
        );
        assert_eq!(state.shared_roots.len(), 1);
        assert_eq!(state.shared_roots["photos"].hash, hash(0xAA));

        let removed = state.unshare_root("photos");
        assert!(removed.is_some());
        assert!(state.shared_roots.is_empty());
    }

    #[test]
    fn share_root_overwrites_existing_label() {
        let mut state = GroupState::new("test".into(), member_id(1), "alice".into());

        state.share_root(
            "music".into(),
            SharedRoot {
                hash: hash(1),
                published_by: member_id(1),
                description: None,
            },
        );
        state.share_root(
            "music".into(),
            SharedRoot {
                hash: hash(2),
                published_by: member_id(1),
                description: None,
            },
        );

        assert_eq!(state.shared_roots.len(), 1);
        assert_eq!(state.shared_roots["music"].hash, hash(2));
    }

    #[test]
    fn cbor_roundtrip() {
        let mut state = GroupState::new("mygroup".into(), member_id(1), "alice".into());
        state.add_member(
            member_id(2),
            MemberInfo {
                name: "bob".into(),
                can_write: true,
            },
        );
        state.share_root(
            "docs".into(),
            SharedRoot {
                hash: hash(0xFF),
                published_by: member_id(2),
                description: Some("shared docs".into()),
            },
        );

        let encoded = minicbor::to_vec(&state).unwrap();
        let decoded: GroupState = minicbor::decode(&encoded).unwrap();
        assert_eq!(state, decoded);
    }

}
