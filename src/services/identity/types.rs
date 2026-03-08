//! Types for the identity service module.
//!
//! Translates the TS SDK identity/types/index.ts.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::wallet::types::Protocol;

/// A displayable identity resolved from the overlay network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayableIdentity {
    /// Display name for the identity.
    pub name: String,
    /// Avatar / profile photo URL or UHRP reference.
    pub avatar_url: String,
    /// Shortened hex public key for display.
    pub abbreviated_key: String,
    /// Full hex-encoded identity key (33-byte compressed public key).
    pub identity_key: String,
    /// Badge icon URL (certifier icon).
    pub badge_icon_url: String,
    /// Badge label describing the certification.
    pub badge_label: String,
    /// Badge click-through URL for more info.
    pub badge_click_url: String,
}

/// Default identity returned when no certificates are found.
pub fn default_identity() -> DisplayableIdentity {
    DisplayableIdentity {
        name: "Unknown Identity".to_string(),
        avatar_url: "XUUB8bbn9fEthk15Ge3zTQXypUShfC94vFjp65v7u5CQ8qkpxzst".to_string(),
        identity_key: String::new(),
        abbreviated_key: String::new(),
        badge_icon_url: "XUUV39HVPkpmMzYNTx7rpKzJvXfeiVyQWg2vfSpjBAuhunTCA9uG".to_string(),
        badge_label: "Not verified by anyone you trust.".to_string(),
        badge_click_url: "https://projectbabbage.com/docs/unknown-identity".to_string(),
    }
}

/// Configuration options for the IdentityClient.
#[derive(Debug, Clone)]
pub struct IdentityClientOptions {
    /// Protocol ID for identity tokens.
    pub protocol_id: Protocol,
    /// Key ID for identity tokens.
    pub key_id: String,
    /// Satoshi amount for identity token outputs.
    pub token_amount: u64,
    /// Output index for identity tokens.
    pub output_index: usize,
}

impl Default for IdentityClientOptions {
    fn default() -> Self {
        IdentityClientOptions {
            protocol_id: Protocol {
                security_level: 1,
                protocol: "identity".to_string(),
            },
            key_id: "1".to_string(),
            token_amount: 1,
            output_index: 0,
        }
    }
}

/// Known identity certificate type hashes (base64-encoded).
pub struct KnownIdentityTypes;

impl KnownIdentityTypes {
    pub const IDENTI_CERT: &'static str = "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY=";
    pub const DISCORD_CERT: &'static str = "2TgqRC35B1zehGmB21xveZNc7i5iqHc0uxMb+1NMPW4=";
    pub const PHONE_CERT: &'static str = "mffUklUzxbHr65xLohn0hRL0Tq2GjW1GYF/OPfzqJ6A=";
    pub const X_CERT: &'static str = "vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc=";
    pub const REGISTRANT: &'static str = "YoPsbfR6YQczjzPdHCoGC7nJsOdPQR50+SYqcWpJ0y0=";
    pub const EMAIL_CERT: &'static str = "exOl3KM0dIJ04EW5pZgbZmPag6MdJXd3/a1enmUU/BA=";
    pub const ANYONE: &'static str = "mfkOMfLDQmrr3SBxBQ5WeE+6Hy3VJRFq6w4A5Ljtlis=";
    pub const SELF_: &'static str = "Hkge6X5JRxt1cWXtHLCrSTg6dCVTxjQJJ48iOYd7n3g=";
    pub const COOL_CERT: &'static str = "AGfk/WrT1eBDXpz3mcw386Zww2HmqcIn3uY6x4Af1eo=";
}

/// Contact stored in the ContactsManager cache.
///
/// Extends DisplayableIdentity with optional metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    /// Display name for the contact.
    pub name: String,
    /// Avatar / profile photo URL or UHRP reference.
    pub avatar_url: String,
    /// Shortened hex public key for display.
    pub abbreviated_key: String,
    /// Full hex-encoded identity key.
    pub identity_key: String,
    /// Badge icon URL.
    pub badge_icon_url: String,
    /// Badge label.
    pub badge_label: String,
    /// Badge click-through URL.
    pub badge_click_url: String,
    /// Optional metadata (notes, aliases, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

impl Contact {
    /// Convert this contact to a DisplayableIdentity.
    pub fn to_displayable(&self) -> DisplayableIdentity {
        DisplayableIdentity {
            name: self.name.clone(),
            avatar_url: self.avatar_url.clone(),
            abbreviated_key: self.abbreviated_key.clone(),
            identity_key: self.identity_key.clone(),
            badge_icon_url: self.badge_icon_url.clone(),
            badge_label: self.badge_label.clone(),
            badge_click_url: self.badge_click_url.clone(),
        }
    }

    /// Create a Contact from a DisplayableIdentity with optional metadata.
    pub fn from_displayable(
        identity: &DisplayableIdentity,
        metadata: Option<HashMap<String, serde_json::Value>>,
    ) -> Self {
        Contact {
            name: identity.name.clone(),
            avatar_url: identity.avatar_url.clone(),
            abbreviated_key: identity.abbreviated_key.clone(),
            identity_key: identity.identity_key.clone(),
            badge_icon_url: identity.badge_icon_url.clone(),
            badge_label: identity.badge_label.clone(),
            badge_click_url: identity.badge_click_url.clone(),
            metadata,
        }
    }
}

/// The protocol used for contacts basket storage.
pub fn contact_protocol() -> Protocol {
    Protocol {
        security_level: 2,
        protocol: "contact".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_identity() {
        let id = default_identity();
        assert_eq!(id.name, "Unknown Identity");
        assert!(id.identity_key.is_empty());
        assert!(id.abbreviated_key.is_empty());
    }

    #[test]
    fn test_default_options() {
        let opts = IdentityClientOptions::default();
        assert_eq!(opts.protocol_id.security_level, 1);
        assert_eq!(opts.protocol_id.protocol, "identity");
        assert_eq!(opts.key_id, "1");
        assert_eq!(opts.token_amount, 1);
        assert_eq!(opts.output_index, 0);
    }

    #[test]
    fn test_known_identity_types() {
        assert_eq!(
            KnownIdentityTypes::IDENTI_CERT,
            "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY="
        );
        assert_eq!(
            KnownIdentityTypes::X_CERT,
            "vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc="
        );
    }

    #[test]
    fn test_contact_roundtrip() {
        let contact = Contact {
            name: "Alice".to_string(),
            avatar_url: "https://example.com/avatar.png".to_string(),
            abbreviated_key: "02abcdef01...".to_string(),
            identity_key: "02abcdef0123456789".to_string(),
            badge_icon_url: "https://example.com/badge.png".to_string(),
            badge_label: "Verified by TestCertifier".to_string(),
            badge_click_url: "https://example.com/info".to_string(),
            metadata: None,
        };

        let json = serde_json::to_string(&contact).unwrap();
        let decoded: Contact = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.name, "Alice");
        assert_eq!(decoded.identity_key, "02abcdef0123456789");
    }

    #[test]
    fn test_contact_to_displayable() {
        let contact = Contact {
            name: "Bob".to_string(),
            avatar_url: "url".to_string(),
            abbreviated_key: "02ab...".to_string(),
            identity_key: "02ab".to_string(),
            badge_icon_url: "icon".to_string(),
            badge_label: "label".to_string(),
            badge_click_url: "click".to_string(),
            metadata: Some(HashMap::from([(
                "note".to_string(),
                serde_json::Value::String("friend".to_string()),
            )])),
        };
        let display = contact.to_displayable();
        assert_eq!(display.name, "Bob");
    }

    #[test]
    fn test_contact_from_displayable() {
        let identity = DisplayableIdentity {
            name: "Charlie".to_string(),
            avatar_url: "url".to_string(),
            abbreviated_key: "02cd...".to_string(),
            identity_key: "02cd".to_string(),
            badge_icon_url: "icon".to_string(),
            badge_label: "label".to_string(),
            badge_click_url: "click".to_string(),
        };
        let contact = Contact::from_displayable(&identity, None);
        assert_eq!(contact.name, "Charlie");
        assert!(contact.metadata.is_none());
    }

    #[test]
    fn test_contact_protocol() {
        let proto = contact_protocol();
        assert_eq!(proto.security_level, 2);
        assert_eq!(proto.protocol, "contact");
    }
}
