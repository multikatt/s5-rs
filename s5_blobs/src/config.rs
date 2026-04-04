use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct PeerConfigBlobs {
    /// Names of stores this peer can read and query
    #[serde(default)]
    pub readable_stores: Vec<String>,
    #[serde(default)]
    pub store_uploads_in: Option<String>,
    /// When true, skip the per-node pin check for downloads/queries.
    /// Useful for group sharing where blobs aren't pinned per remote node.
    #[serde(default)]
    pub skip_pin_check: bool,
}
