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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{MemberInfo, SharedRoot};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory registry for testing.
    #[derive(Debug, Default)]
    struct MemRegistry {
        entries: Mutex<HashMap<[u8; 32], StreamMessage>>,
    }

    impl MemRegistry {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }
    }

    fn key_bytes(key: &StreamKey) -> [u8; 32] {
        match key {
            StreamKey::PublicKeyEd25519(k) => *k,
            _ => panic!("unexpected key type in test"),
        }
    }

    #[async_trait]
    impl RegistryApi for MemRegistry {
        async fn get(&self, key: &StreamKey) -> Result<Option<StreamMessage>> {
            Ok(self.entries.lock().unwrap().get(&key_bytes(key)).cloned())
        }

        async fn set(&self, message: StreamMessage) -> Result<()> {
            let k = key_bytes(&message.key);
            self.entries.lock().unwrap().insert(k, message);
            Ok(())
        }

        async fn delete(&self, key: &StreamKey) -> Result<()> {
            self.entries.lock().unwrap().remove(&key_bytes(key));
            Ok(())
        }
    }

    fn member_id(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[tokio::test]
    async fn create_and_load_state() {
        let reg = MemRegistry::new();
        let mut mgr =
            GroupManager::create(reg.clone(), "testgroup".into(), member_id(1), "alice".into())
                .await
                .unwrap();

        assert!(mgr.can_write());

        let state = mgr.load_state().await.unwrap().unwrap();
        assert_eq!(state.name, "testgroup");
        assert_eq!(state.members.len(), 1);
        assert!(state.is_member(&member_id(1)));
    }

    #[tokio::test]
    async fn open_rw_loads_existing_state() {
        let reg = MemRegistry::new();
        let mgr =
            GroupManager::create(reg.clone(), "g".into(), member_id(1), "alice".into())
                .await
                .unwrap();

        let sk = SigningKey::from_bytes(&mgr.signing_key_bytes().unwrap());

        let mut mgr2 = GroupManager::open_rw(reg.clone(), sk).await.unwrap();
        assert!(mgr2.can_write());

        let state = mgr2.load_state().await.unwrap().unwrap();
        assert_eq!(state.name, "g");
    }

    #[tokio::test]
    async fn open_ro_cannot_publish() {
        let reg = MemRegistry::new();
        let mgr =
            GroupManager::create(reg.clone(), "g".into(), member_id(1), "alice".into())
                .await
                .unwrap();

        let group_id = *mgr.group_id();
        let mut ro = GroupManager::open_ro(reg.clone(), group_id).await.unwrap();
        assert!(!ro.can_write());

        let state = ro.load_state().await.unwrap().unwrap();
        assert_eq!(state.name, "g");

        // Publishing should fail for read-only
        let err = ro.publish_state(&state).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn publish_updates_are_visible() {
        let reg = MemRegistry::new();
        let mut mgr =
            GroupManager::create(reg.clone(), "g".into(), member_id(1), "alice".into())
                .await
                .unwrap();

        // Load, modify, publish
        let mut state = mgr.load_state().await.unwrap().unwrap();
        state.add_member(
            member_id(2),
            MemberInfo {
                name: "bob".into(),
                can_write: true,
            },
        );
        state.share_root(
            "photos".into(),
            SharedRoot {
                hash: [0xAA; 32],
                published_by: member_id(1),
                description: None,
            },
        );
        mgr.publish_state(&state).await.unwrap();

        // Re-load and verify
        let reloaded = mgr.load_state().await.unwrap().unwrap();
        assert_eq!(reloaded.members.len(), 2);
        assert!(reloaded.is_member(&member_id(2)));
        assert_eq!(reloaded.shared_roots.len(), 1);
        assert_eq!(reloaded.shared_roots["photos"].hash, [0xAA; 32]);
    }

    #[tokio::test]
    async fn multiple_publishes_increment_revision() {
        let reg = MemRegistry::new();
        let mut mgr =
            GroupManager::create(reg.clone(), "g".into(), member_id(1), "alice".into())
                .await
                .unwrap();

        let mut state = mgr.load_state().await.unwrap().unwrap();
        state.add_member(
            member_id(2),
            MemberInfo {
                name: "bob".into(),
                can_write: false,
            },
        );
        mgr.publish_state(&state).await.unwrap();

        state.add_member(
            member_id(3),
            MemberInfo {
                name: "charlie".into(),
                can_write: false,
            },
        );
        mgr.publish_state(&state).await.unwrap();

        let final_state = mgr.load_state().await.unwrap().unwrap();
        assert_eq!(final_state.members.len(), 3);
    }

    #[tokio::test]
    async fn second_manager_sees_updates_from_first() {
        let reg = MemRegistry::new();
        let mut mgr1 =
            GroupManager::create(reg.clone(), "g".into(), member_id(1), "alice".into())
                .await
                .unwrap();

        let sk = SigningKey::from_bytes(&mgr1.signing_key_bytes().unwrap());

        // mgr1 adds a member
        let mut state = mgr1.load_state().await.unwrap().unwrap();
        state.add_member(
            member_id(2),
            MemberInfo {
                name: "bob".into(),
                can_write: true,
            },
        );
        mgr1.publish_state(&state).await.unwrap();

        // mgr2 opens and sees the update
        let mut mgr2 = GroupManager::open_rw(reg.clone(), sk).await.unwrap();
        let state2 = mgr2.load_state().await.unwrap().unwrap();
        assert_eq!(state2.members.len(), 2);
        assert!(state2.is_member(&member_id(2)));
    }

    #[tokio::test]
    async fn open_ro_nonexistent_group_returns_none() {
        let reg = MemRegistry::new();
        let mut mgr = GroupManager::open_ro(reg, [0xFF; 32]).await.unwrap();
        assert!(mgr.load_state().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn rw_member_adds_ro_member_on_their_behalf() {
        let reg = MemRegistry::new();

        // Alice creates the group
        let mut mgr =
            GroupManager::create(reg.clone(), "g".into(), member_id(1), "alice".into())
                .await
                .unwrap();

        let group_id = *mgr.group_id();
        let sk = SigningKey::from_bytes(&mgr.signing_key_bytes().unwrap());

        // Charlie is a read-only member — can't publish state
        let mut ro = GroupManager::open_ro(reg.clone(), group_id).await.unwrap();
        assert!(!ro.can_write());

        let state = ro.load_state().await.unwrap().unwrap();
        assert!(!state.is_member(&member_id(3)));

        // Alice (write-capable) registers Charlie
        let mut state = mgr.load_state().await.unwrap().unwrap();
        state.add_member(
            member_id(3),
            MemberInfo {
                name: "charlie".into(),
                can_write: false,
            },
        );
        mgr.publish_state(&state).await.unwrap();

        // Charlie can now see themselves via read-only access
        let mut ro2 = GroupManager::open_ro(reg.clone(), group_id).await.unwrap();
        let state2 = ro2.load_state().await.unwrap().unwrap();
        assert!(state2.is_member(&member_id(3)));
        assert!(!state2.members[&member_id(3)].can_write);

        // A second rw manager also sees Charlie
        let mut mgr2 = GroupManager::open_rw(reg.clone(), sk).await.unwrap();
        let state3 = mgr2.load_state().await.unwrap().unwrap();
        assert_eq!(state3.members.len(), 2);
        assert!(state3.is_member(&member_id(3)));
    }
}
