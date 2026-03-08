//! Session management for the BRC-31 authentication protocol.
//!
//! SessionManager tracks authenticated sessions by both session nonce
//! (primary key) and peer identity key (secondary index), supporting
//! multiple concurrent sessions per identity key.
//!
//! Translated from TS SDK SessionManager.ts and Go SDK session_manager.go.

use std::collections::{HashMap, HashSet};

use super::types::PeerSession;

/// Manages authenticated peer sessions with dual-index tracking.
///
/// Sessions are indexed by:
/// - Session nonce (primary key, unique per session)
/// - Identity key (secondary index, one-to-many)
///
/// This allows lookup by either nonce or identity key, with the identity
/// key lookup returning the "best" session (preferring authenticated ones).
pub struct SessionManager {
    /// Maps session_nonce -> PeerSession (primary index).
    nonce_to_session: HashMap<String, PeerSession>,
    /// Maps identity_key -> set of session nonces (secondary index).
    identity_to_nonces: HashMap<String, HashSet<String>>,
}

impl SessionManager {
    /// Create a new empty SessionManager.
    pub fn new() -> Self {
        SessionManager {
            nonce_to_session: HashMap::new(),
            identity_to_nonces: HashMap::new(),
        }
    }

    /// Add a session to the manager.
    ///
    /// Indexes by session_nonce (primary) and peer_identity_key (secondary).
    /// Does NOT overwrite existing sessions for the same identity key,
    /// allowing multiple concurrent sessions per peer.
    pub fn add_session(&mut self, session: PeerSession) {
        let nonce = session.session_nonce.clone();
        let identity = session.peer_identity_key.clone();

        self.nonce_to_session.insert(nonce.clone(), session);

        self.identity_to_nonces
            .entry(identity)
            .or_default()
            .insert(nonce);
    }

    /// Get a session by nonce (immutable reference).
    pub fn get_session(&self, nonce: &str) -> Option<&PeerSession> {
        self.nonce_to_session.get(nonce)
    }

    /// Get a session by nonce (mutable reference).
    pub fn get_session_mut(&mut self, nonce: &str) -> Option<&mut PeerSession> {
        self.nonce_to_session.get_mut(nonce)
    }

    /// Get all sessions for a given identity key.
    pub fn get_sessions_for_identity(&self, identity_key: &str) -> Vec<&PeerSession> {
        match self.identity_to_nonces.get(identity_key) {
            Some(nonces) => nonces
                .iter()
                .filter_map(|n| self.nonce_to_session.get(n))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Get the "best" session for an identity key (prefers authenticated).
    ///
    /// Matches TS SDK SessionManager.getSession() behavior: if the identifier
    /// is a session nonce, returns that exact session. If it is an identity key,
    /// returns the best (authenticated preferred) session.
    pub fn get_session_by_identifier(&self, identifier: &str) -> Option<&PeerSession> {
        // Try as direct nonce first
        if let Some(session) = self.nonce_to_session.get(identifier) {
            return Some(session);
        }

        // Try as identity key
        let nonces = self.identity_to_nonces.get(identifier)?;
        let mut best: Option<&PeerSession> = None;
        for nonce in nonces {
            if let Some(session) = self.nonce_to_session.get(nonce) {
                match best {
                    None => best = Some(session),
                    Some(b) => {
                        // Prefer authenticated sessions
                        if session.is_authenticated && !b.is_authenticated {
                            best = Some(session);
                        }
                    }
                }
            }
        }
        best
    }

    /// Check if a session exists for a given nonce.
    pub fn has_session(&self, nonce: &str) -> bool {
        self.nonce_to_session.contains_key(nonce)
    }

    /// Check if any session exists for a given identifier (nonce or identity key).
    pub fn has_session_by_identifier(&self, identifier: &str) -> bool {
        if self.nonce_to_session.contains_key(identifier) {
            return true;
        }
        match self.identity_to_nonces.get(identifier) {
            Some(nonces) => !nonces.is_empty(),
            None => false,
        }
    }

    /// Replace a session at the given nonce.
    pub fn update_session(&mut self, nonce: &str, session: PeerSession) {
        // Remove old identity mapping if the identity key changed
        if let Some(old_session) = self.nonce_to_session.get(nonce) {
            let old_identity = old_session.peer_identity_key.clone();
            if old_identity != session.peer_identity_key {
                if let Some(nonces) = self.identity_to_nonces.get_mut(&old_identity) {
                    nonces.remove(nonce);
                    if nonces.is_empty() {
                        self.identity_to_nonces.remove(&old_identity);
                    }
                }
            }
        }

        let new_identity = session.peer_identity_key.clone();
        self.nonce_to_session.insert(nonce.to_string(), session);
        self.identity_to_nonces
            .entry(new_identity)
            .or_default()
            .insert(nonce.to_string());
    }

    /// Remove a session by nonce. Returns the removed session if found.
    pub fn remove_session(&mut self, nonce: &str) -> Option<PeerSession> {
        if let Some(session) = self.nonce_to_session.remove(nonce) {
            // Clean up identity index
            if let Some(nonces) = self.identity_to_nonces.get_mut(&session.peer_identity_key) {
                nonces.remove(nonce);
                if nonces.is_empty() {
                    self.identity_to_nonces.remove(&session.peer_identity_key);
                }
            }
            Some(session)
        } else {
            None
        }
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(nonce: &str, identity: &str, authenticated: bool) -> PeerSession {
        PeerSession {
            session_nonce: nonce.to_string(),
            peer_identity_key: identity.to_string(),
            peer_nonce: format!("peer_{}", nonce),
            is_authenticated: authenticated,
        }
    }

    #[test]
    fn test_add_and_get_session() {
        let mut mgr = SessionManager::new();
        let session = make_session("nonce1", "id_key_A", true);
        mgr.add_session(session.clone());

        let retrieved = mgr.get_session("nonce1").unwrap();
        assert_eq!(retrieved.session_nonce, "nonce1");
        assert_eq!(retrieved.peer_identity_key, "id_key_A");
        assert!(retrieved.is_authenticated);
    }

    #[test]
    fn test_has_session() {
        let mut mgr = SessionManager::new();
        assert!(!mgr.has_session("nonce1"));

        mgr.add_session(make_session("nonce1", "id_key_A", true));
        assert!(mgr.has_session("nonce1"));
        assert!(!mgr.has_session("nonce2"));
    }

    #[test]
    fn test_remove_session() {
        let mut mgr = SessionManager::new();
        mgr.add_session(make_session("nonce1", "id_key_A", true));

        let removed = mgr.remove_session("nonce1").unwrap();
        assert_eq!(removed.session_nonce, "nonce1");
        assert!(!mgr.has_session("nonce1"));

        // Identity index should also be cleaned up
        let sessions = mgr.get_sessions_for_identity("id_key_A");
        assert!(sessions.is_empty());
    }

    #[test]
    fn test_get_sessions_for_identity() {
        let mut mgr = SessionManager::new();
        mgr.add_session(make_session("nonce1", "id_key_A", true));
        mgr.add_session(make_session("nonce2", "id_key_A", false));
        mgr.add_session(make_session("nonce3", "id_key_B", true));

        let a_sessions = mgr.get_sessions_for_identity("id_key_A");
        assert_eq!(a_sessions.len(), 2);

        let b_sessions = mgr.get_sessions_for_identity("id_key_B");
        assert_eq!(b_sessions.len(), 1);

        let c_sessions = mgr.get_sessions_for_identity("id_key_C");
        assert!(c_sessions.is_empty());
    }

    #[test]
    fn test_get_session_by_identifier() {
        let mut mgr = SessionManager::new();
        mgr.add_session(make_session("nonce1", "id_key_A", false));
        mgr.add_session(make_session("nonce2", "id_key_A", true));

        // Direct nonce lookup
        let s = mgr.get_session_by_identifier("nonce1").unwrap();
        assert_eq!(s.session_nonce, "nonce1");

        // Identity key lookup should prefer authenticated session
        let best = mgr.get_session_by_identifier("id_key_A").unwrap();
        assert!(best.is_authenticated);
    }

    #[test]
    fn test_has_session_by_identifier() {
        let mut mgr = SessionManager::new();
        mgr.add_session(make_session("nonce1", "id_key_A", true));

        assert!(mgr.has_session_by_identifier("nonce1"));
        assert!(mgr.has_session_by_identifier("id_key_A"));
        assert!(!mgr.has_session_by_identifier("unknown"));
    }

    #[test]
    fn test_update_session() {
        let mut mgr = SessionManager::new();
        mgr.add_session(make_session("nonce1", "id_key_A", false));

        // Update to authenticated
        let updated = make_session("nonce1", "id_key_A", true);
        mgr.update_session("nonce1", updated);

        let s = mgr.get_session("nonce1").unwrap();
        assert!(s.is_authenticated);
    }

    #[test]
    fn test_get_session_mut() {
        let mut mgr = SessionManager::new();
        mgr.add_session(make_session("nonce1", "id_key_A", false));

        let s = mgr.get_session_mut("nonce1").unwrap();
        s.is_authenticated = true;

        let s2 = mgr.get_session("nonce1").unwrap();
        assert!(s2.is_authenticated);
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut mgr = SessionManager::new();
        assert!(mgr.remove_session("nonexistent").is_none());
    }

    #[test]
    fn test_identity_cleanup_on_remove_last_session() {
        let mut mgr = SessionManager::new();
        mgr.add_session(make_session("nonce1", "id_key_A", true));
        mgr.add_session(make_session("nonce2", "id_key_A", true));

        mgr.remove_session("nonce1");
        // Still has one session for identity
        assert!(mgr.has_session_by_identifier("id_key_A"));

        mgr.remove_session("nonce2");
        // Now identity should be cleaned up
        assert!(!mgr.has_session_by_identifier("id_key_A"));
    }
}
