//! Storage module for UHRP file upload and download.
//!
//! Provides StorageUtils for UHRP URL encoding/decoding,
//! StorageUploader for authenticated file uploads, and
//! StorageDownloader for hash-verified downloads.

pub mod storage_utils;

#[cfg(feature = "network")]
pub mod storage_downloader;
#[cfg(feature = "network")]
pub mod storage_uploader;

pub use storage_utils::{get_hash_from_url, get_url_for_file, get_url_for_hash, is_valid_url};

#[cfg(feature = "network")]
pub use storage_downloader::{DownloadResult, StorageDownloader, StorageDownloaderConfig};
#[cfg(feature = "network")]
pub use storage_uploader::{StorageUploader, StorageUploaderConfig, UploadFileResult};
