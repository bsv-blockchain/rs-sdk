//! LockingScript: type-safe wrapper around Script for output scripts.

use crate::script::script::Script;
use std::ops::Deref;

/// A locking script (scriptPubKey) wrapping a generic Script.
///
/// Uses `Deref` to Script for transparent access to all Script methods.
/// Provides type-safety to distinguish output scripts from input scripts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockingScript(pub(crate) Script);

impl Deref for LockingScript {
    type Target = Script;
    fn deref(&self) -> &Script {
        &self.0
    }
}

impl LockingScript {
    /// Create from raw binary bytes.
    pub fn from_binary(bin: &[u8]) -> Self {
        LockingScript(Script::from_binary(bin))
    }

    /// Create from hex string.
    pub fn from_hex(hex: &str) -> Result<Self, crate::script::error::ScriptError> {
        Ok(LockingScript(Script::from_hex(hex)?))
    }

    /// Create from ASM string.
    pub fn from_asm(asm: &str) -> Self {
        LockingScript(Script::from_asm(asm))
    }

    /// Create from an existing Script.
    pub fn from_script(script: Script) -> Self {
        LockingScript(script)
    }
}
