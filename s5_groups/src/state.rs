//! Group state management via the S5 registry.
//!
//! The [`GroupManager`] reads and writes [`GroupState`] to the S5 registry
//! using the group's Ed25519 keypair for authentication.

use anyhow::{Context, Result, anyhow};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use s5_core::{Hash, MessageType, RegistryApi, StreamKey, StreamMessage};
use std::sync::Arc;

use crate::types::{GroupId, GroupState};

/// Manages a single group's lifecycle: create, load, update, join, leave, share.
pub struct GroupManager {
    /// The group's Ed25519 signing key (required for write operations).
    /// None if this is a read-only view.
    signing_key: Option<SigningKey>,

    /// The group's public key (always available).
    group_id: GroupId,

    /// The S5 registry used to store/retrieve group state.
    registry: Arc<dyn RegistryApi + Send + Sync>,

    /// Current revision of the group state in the registry.
    revision: u64,
}

impl GroupManager {
    /// Create a new group and publish its initial state to the registry.
    pub async fn create(
        registry: Arc<dyn RegistryApi + Send + Sync>,
        group_name: String,
        founder_id: [u8; 32],
        founder_name: String,
    ) -> Result<Self> {
        // Generate a new keypair for the group
        let mut secret_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key: VerifyingKey = (&signing_key).into();
        let group_id = verifying_key.to_bytes();

        let state = GroupState::new(group_name, founder_id, founder_name);

        let mut mgr = Self {
            signing_key: Some(signing_key),
            group_id,
            registry,
            revision: 0,
        };

        mgr.publish_state(&state).await?;
        Ok(mgr)
    }

    /// Open an existing group for read-write access (requires the group secret key).
    pub async fn open_rw(
        registry: Arc<dyn RegistryApi + Send + Sync>,
        signing_key: SigningKey,
    ) -> Result<Self> {
        let verifying_key: VerifyingKey = (&signing_key).into();
        let group_id = verifying_key.to_bytes();

        let mut mgr = Self {
            signing_key: Some(signing_key),
            group_id,
            registry,
            revision: 0,
        };

        // Set revision to one past the current so next publish wins
        if let Some(msg) = mgr.load_message().await? {
            mgr.revision = msg.revision + 1;
        }

        Ok(mgr)
    }

    /// Open an existing group for read-only access (only needs the public key).
    pub async fn open_ro(
        registry: Arc<dyn RegistryApi + Send + Sync>,
        group_id: GroupId,
    ) -> Result<Self> {
        let mut mgr = Self {
            signing_key: None,
            group_id,
            registry,
            revision: 0,
        };

        if let Some(msg) = mgr.load_message().await? {
            mgr.revision = msg.revision;
        }

        Ok(mgr)
    }

    /// The group's public key / identity.
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Whether this manager has write access.
    pub fn can_write(&self) -> bool {
        self.signing_key.is_some()
    }

    /// Load the current group state from the registry.
    pub async fn load_state(&mut self) -> Result<Option<GroupState>> {
        let msg = match self.load_message().await? {
            Some(m) => m,
            None => return Ok(None),
        };

        self.revision = msg.revision + 1;

        let data = msg
            .data
            .as_ref()
            .ok_or_else(|| anyhow!("group registry entry has no inline data"))?;

        let state: GroupState = minicbor::decode(data)
            .context("failed to decode group state from CBOR")?;

        Ok(Some(state))
    }

    /// Publish an updated group state to the registry.
    ///
    /// Increments the revision automatically.
    pub async fn publish_state(&mut self, state: &GroupState) -> Result<()> {
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or_else(|| anyhow!("cannot publish: read-only group access"))?;

        let data = minicbor::to_vec(state)
            .context("failed to encode group state as CBOR")?;
        let data = bytes::Bytes::from(data);

        let hash = Hash::from(*blake3::hash(&data).as_bytes());

        let revision = self.revision;
        let pub_key_bytes = self.group_id;

        // Build the signing payload (matches the S5 registry signature scheme)
        let mut sign_bytes = Vec::new();
        sign_bytes.push(MessageType::Registry as u8);
        sign_bytes.push(StreamKey::PUBLIC_KEY_ED25519_ID);
        sign_bytes.extend_from_slice(&pub_key_bytes);
        sign_bytes.extend_from_slice(&revision.to_be_bytes());
        sign_bytes.push(0x21); // Blake3 hash type marker
        sign_bytes.extend_from_slice(hash.as_ref());

        let signature = signing_key.sign(&sign_bytes);

        let stream_key = StreamKey::PublicKeyEd25519(pub_key_bytes);
        let entry = StreamMessage::new(
            MessageType::Registry,
            stream_key,
            revision,
            hash,
            signature.to_bytes().to_vec().into_boxed_slice(),
            Some(data),
        )?;

        self.registry.set(entry).await?;
        self.revision += 1;

        Ok(())
    }

    /// Get the signing key bytes (for inclusion in invite links).
    /// Returns None for read-only managers.
    pub fn signing_key_bytes(&self) -> Option<[u8; 32]> {
        self.signing_key.as_ref().map(|sk| sk.to_bytes())
    }

    /// Load the raw registry message for this group.
    async fn load_message(&self) -> Result<Option<StreamMessage>> {
        let stream_key = StreamKey::PublicKeyEd25519(self.group_id);
        self.registry.get(&stream_key).await
    }
}
