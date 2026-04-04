//! Invite links for joining groups.
//!
//! An invite encodes enough information for a new member to find and join a group:
//! - The group's public key (identity)
//! - One or more bootstrap peer addresses (endpoint ID + relay URL + IPs)
//! - Capability level (read-only or read-write)
//!
//! For read-write invites, the group's secret key is included so the new member
//! can publish state updates. For read-only invites, only the public key is shared.
//!
//! # Wire format
//!
//! Invites are CBOR-encoded and then base64url-encoded for easy sharing as text.
//! Bootstrap peer addresses are stored as postcard-serialized `iroh::EndpointAddr`
//! bytes within the CBOR structure, since `EndpointAddr` uses serde but the invite
//! uses minicbor.

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use iroh::EndpointAddr;
use minicbor::{Decode, Encode};

use crate::types::GroupId;

/// What level of access an invite grants.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum InviteCapability {
    /// Can read shared content but cannot modify group state.
    #[n(0)]
    ReadOnly,

    /// Can read and write: modify membership, share/unshare roots.
    /// Contains the group's Ed25519 secret key (32 bytes).
    #[n(1)]
    ReadWrite {
        #[n(0)]
        secret_key: [u8; 32],
    },
}

/// A serializable invite token for joining a group.
///
/// Bootstrap peers are stored as opaque postcard-encoded bytes
/// (each element is a serialized `iroh::EndpointAddr`).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct GroupInvite {
    /// The group's Ed25519 public key.
    #[n(0)]
    pub group_id: GroupId,

    /// Postcard-serialized `EndpointAddr` entries for bootstrap peers.
    #[n(1)]
    bootstrap_peers_raw: Vec<minicbor::bytes::ByteVec>,

    /// Access level granted by this invite.
    #[n(2)]
    pub capability: InviteCapability,
}

impl GroupInvite {
    /// Create a read-write invite.
    pub fn new_rw(
        group_id: GroupId,
        secret_key: [u8; 32],
        bootstrap_peers: Vec<EndpointAddr>,
    ) -> Result<Self> {
        Ok(Self {
            group_id,
            bootstrap_peers_raw: serialize_peers(&bootstrap_peers)?,
            capability: InviteCapability::ReadWrite { secret_key },
        })
    }

    /// Create a read-only invite.
    pub fn new_ro(group_id: GroupId, bootstrap_peers: Vec<EndpointAddr>) -> Result<Self> {
        Ok(Self {
            group_id,
            bootstrap_peers_raw: serialize_peers(&bootstrap_peers)?,
            capability: InviteCapability::ReadOnly,
        })
    }

    /// Get the bootstrap peer addresses.
    pub fn bootstrap_peers(&self) -> Result<Vec<EndpointAddr>> {
        self.bootstrap_peers_raw
            .iter()
            .map(|raw| {
                postcard::from_bytes(raw)
                    .map_err(|e| anyhow!("failed to deserialize bootstrap peer: {}", e))
            })
            .collect()
    }

    /// Whether this invite grants write access.
    pub fn is_read_write(&self) -> bool {
        matches!(self.capability, InviteCapability::ReadWrite { .. })
    }

    /// Serialize to a base64url string for sharing.
    pub fn to_string(&self) -> Result<String> {
        let cbor = minicbor::to_vec(self).context("failed to encode invite")?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cbor))
    }

    /// Deserialize from a base64url string.
    pub fn from_str(s: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s.trim())
            .context("invalid base64url in invite")?;
        minicbor::decode(&bytes).map_err(|e| anyhow!("invalid invite data: {}", e))
    }
}

fn serialize_peers(peers: &[EndpointAddr]) -> Result<Vec<minicbor::bytes::ByteVec>> {
    peers
        .iter()
        .map(|addr| {
            let bytes = postcard::to_allocvec(addr)
                .map_err(|e| anyhow!("failed to serialize peer address: {}", e))?;
            Ok(minicbor::bytes::ByteVec::from(bytes))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_endpoint_addr() -> EndpointAddr {
        // Generate a valid ed25519 keypair for the endpoint ID
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        let secret = iroh::SecretKey::from_bytes(&bytes);
        let id = secret.public();
        EndpointAddr::from(id)
    }

    #[test]
    fn roundtrip_ro_invite() {
        let group_id = [1u8; 32];
        let addr = test_endpoint_addr();
        let expected_id = *addr.id.as_bytes();
        let invite = GroupInvite::new_ro(group_id, vec![addr]).unwrap();

        let encoded = invite.to_string().unwrap();
        let decoded = GroupInvite::from_str(&encoded).unwrap();

        assert_eq!(invite, decoded);
        assert!(!decoded.is_read_write());

        let peers = decoded.bootstrap_peers().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(*peers[0].id.as_bytes(), expected_id);
    }

    #[test]
    fn roundtrip_rw_invite() {
        let group_id = [1u8; 32];
        let secret = [3u8; 32];
        let invite =
            GroupInvite::new_rw(group_id, secret, vec![test_endpoint_addr()]).unwrap();

        let encoded = invite.to_string().unwrap();
        let decoded = GroupInvite::from_str(&encoded).unwrap();

        assert_eq!(invite, decoded);
        assert!(decoded.is_read_write());
    }
}
