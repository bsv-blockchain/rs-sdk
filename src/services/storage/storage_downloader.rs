//! StorageDownloader for downloading files via UHRP protocol.
//!
//! Translates the TS SDK StorageDownloader.ts. Resolves UHRP URLs via
//! LookupResolver to find hosts, downloads content, and verifies the
//! SHA-256 hash matches the expected hash from the URL.

use crate::primitives::hash::sha256;
use crate::primitives::utils::to_hex;
use crate::services::overlay_tools::lookup_resolver::LookupResolver;
use crate::services::overlay_tools::types::{
    LookupAnswer, LookupQuestion, LookupResolverConfig, Network,
};
use crate::services::ServicesError;

use super::storage_utils::{get_hash_from_url, is_valid_url};

/// Configuration for the StorageDownloader.
#[derive(Debug, Clone)]
pub struct StorageDownloaderConfig {
    /// Network preset for overlay services.
    pub network: Network,
}

impl Default for StorageDownloaderConfig {
    fn default() -> Self {
        StorageDownloaderConfig {
            network: Network::Mainnet,
        }
    }
}

/// Result of a successful download.
#[derive(Debug)]
pub struct DownloadResult {
    /// Downloaded file data.
    pub data: Vec<u8>,
    /// MIME type from the response, if available.
    pub mime_type: Option<String>,
}

/// StorageDownloader resolves UHRP URLs and downloads files with hash verification.
///
/// Uses a LookupResolver to query the UHRP overlay service for hosts that serve
/// a given content hash, then downloads from them and verifies integrity.
pub struct StorageDownloader {
    /// LookupResolver for UHRP host discovery.
    resolver: LookupResolver,
    /// HTTP client for downloads.
    client: reqwest::Client,
}

impl StorageDownloader {
    /// Create a new StorageDownloader with the given configuration.
    pub fn new(config: StorageDownloaderConfig) -> Self {
        let resolver_config = LookupResolverConfig {
            network: config.network,
            ..Default::default()
        };
        StorageDownloader {
            resolver: LookupResolver::new(resolver_config),
            client: reqwest::Client::new(),
        }
    }

    /// Resolve a UHRP URL to a list of HTTP URLs where the content can be downloaded.
    ///
    /// Queries the ls_uhrp lookup service via the overlay network and decodes
    /// PushDrop outputs to extract host URLs, filtering out expired entries.
    pub async fn resolve(&self, uhrp_url: &str) -> Result<Vec<String>, ServicesError> {
        let question = LookupQuestion {
            service: "ls_uhrp".to_string(),
            query: serde_json::json!({ "uhrpUrl": uhrp_url }),
        };

        let answer = self.resolver.query(&question, None).await?;

        match answer {
            LookupAnswer::OutputList { outputs } => {
                let mut urls = Vec::new();
                let current_time = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                for entry in &outputs {
                    // Decode PushDrop output to extract URL and expiry.
                    // PushDrop fields for UHRP: [uhrpUrl, hash, hostUrl, expiryTime, ...]
                    // We attempt to parse the beef into a transaction and extract fields.
                    if let Ok(url_str) = Self::extract_host_url(
                        &entry.beef,
                        entry.output_index as usize,
                        current_time,
                    ) {
                        urls.push(url_str);
                    }
                }
                Ok(urls)
            }
            _ => Err(ServicesError::Storage(
                "lookup answer must be an output list".into(),
            )),
        }
    }

    /// Extract the host URL from a BEEF-encoded transaction output.
    ///
    /// Decodes the PushDrop fields and returns the host URL if the entry
    /// has not expired.
    fn extract_host_url(
        beef_bytes: &[u8],
        output_index: usize,
        current_time: u64,
    ) -> Result<String, ServicesError> {
        use crate::transaction::beef::Beef;
        use std::io::Cursor;

        let beef = Beef::from_binary(&mut Cursor::new(beef_bytes))
            .map_err(|e| ServicesError::Storage(format!("failed to parse BEEF: {}", e)))?;

        // Get the last transaction in the BEEF (the tip/newest).
        let beef_tx = beef
            .txs
            .last()
            .ok_or_else(|| ServicesError::Storage("BEEF contains no transactions".into()))?;
        let tx = beef_tx
            .tx
            .as_ref()
            .ok_or_else(|| ServicesError::Storage("BEEF transaction has no tx data".into()))?;

        if output_index >= tx.outputs.len() {
            return Err(ServicesError::Storage("output index out of bounds".into()));
        }

        let output = &tx.outputs[output_index];
        let chunks = output.locking_script.chunks();

        // PushDrop fields are the data-push chunks before OP_DROP/OP_2DROP.
        // Extract data fields (non-opcode chunks with data).
        let mut fields: Vec<Vec<u8>> = Vec::new();
        for chunk in chunks {
            if let Some(ref data) = chunk.data {
                // Stop at pubkey (33 bytes compressed) before OP_CHECKSIG
                if data.len() == 33 && (data[0] == 0x02 || data[0] == 0x03) {
                    break;
                }
                fields.push(data.clone());
            } else {
                // Encountered opcode (OP_DROP etc.), stop collecting fields
                break;
            }
        }

        // Expected fields: [uhrpUrl, hash, hostUrl, expiryTime]
        if fields.len() < 4 {
            return Err(ServicesError::Storage(
                "insufficient PushDrop fields".into(),
            ));
        }

        // Check expiry time (field[3] is a varint-encoded timestamp)
        let expiry = read_varint_from_field(&fields[3]);
        if expiry < current_time {
            return Err(ServicesError::Storage("entry expired".into()));
        }

        // Host URL is field[2] as UTF-8
        String::from_utf8(fields[2].clone())
            .map_err(|e| ServicesError::Storage(format!("invalid host URL: {}", e)))
    }

    /// Download content from a UHRP URL, verifying hash integrity.
    ///
    /// Resolves the UHRP URL to download hosts, attempts to download from each,
    /// and verifies the SHA-256 hash of the downloaded data matches the expected
    /// hash encoded in the UHRP URL.
    pub async fn download(&self, uhrp_url: &str) -> Result<DownloadResult, ServicesError> {
        if !is_valid_url(uhrp_url) {
            return Err(ServicesError::Storage("invalid UHRP URL".into()));
        }

        let expected_hash = get_hash_from_url(uhrp_url)?;
        let expected_hex = to_hex(&expected_hash);

        let download_urls = self.resolve(uhrp_url).await?;

        if download_urls.is_empty() {
            return Err(ServicesError::Storage(
                "no one currently hosts this file".into(),
            ));
        }

        for url in &download_urls {
            let result = self.client.get(url).send().await;
            let response = match result {
                Ok(r) if r.status().is_success() => r,
                _ => continue,
            };

            let mime_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let data = match response.bytes().await {
                Ok(b) => b.to_vec(),
                Err(_) => continue,
            };

            // Verify hash integrity
            let actual_hash = sha256(&data);
            let actual_hex = to_hex(&actual_hash);

            if actual_hex != expected_hex {
                // Data integrity error, try next host
                continue;
            }

            return Ok(DownloadResult { data, mime_type });
        }

        Err(ServicesError::Storage(format!(
            "unable to download content from {}",
            uhrp_url
        )))
    }
}

/// Read a varint-like number from a PushDrop field.
/// Simple approach: treat the bytes as a little-endian integer.
fn read_varint_from_field(data: &[u8]) -> u64 {
    if data.is_empty() {
        return 0;
    }
    // For the UHRP expiry, this is typically a small varint.
    // Read up to 8 bytes as little-endian.
    let mut bytes = [0u8; 8];
    let len = data.len().min(8);
    bytes[..len].copy_from_slice(&data[..len]);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_verification_logic() {
        // Verify that our hash verification approach works correctly.
        let data = b"test content for download verification";
        let hash = sha256(data);
        let expected_hex = to_hex(&hash);

        // Hash of the same data should match.
        let actual_hash = sha256(data);
        let actual_hex = to_hex(&actual_hash);
        assert_eq!(expected_hex, actual_hex);

        // Hash of different data should not match.
        let other_hash = sha256(b"different content");
        let other_hex = to_hex(&other_hash);
        assert_ne!(expected_hex, other_hex);
    }

    #[test]
    fn test_read_varint_from_field() {
        // 4-byte little-endian timestamp (e.g., 1700000000 = 0x6560A380)
        let bytes = 1700000000u64.to_le_bytes();
        let result = read_varint_from_field(&bytes);
        assert_eq!(result, 1700000000);
    }

    #[test]
    fn test_read_varint_empty() {
        assert_eq!(read_varint_from_field(&[]), 0);
    }

    #[test]
    fn test_default_config() {
        let config = StorageDownloaderConfig::default();
        assert_eq!(config.network, Network::Mainnet);
    }
}
