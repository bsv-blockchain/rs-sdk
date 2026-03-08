//! UnlockingScript: type-safe wrapper around Script for input scripts.

use crate::script::script::Script;
use std::ops::Deref;

/// An unlocking script (scriptSig) wrapping a generic Script.
///
/// Uses `Deref` to Script for transparent access to all Script methods.
/// Provides type-safety to distinguish input scripts from output scripts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockingScript(pub(crate) Script);

impl Deref for UnlockingScript {
    type Target = Script;
    fn deref(&self) -> &Script {
        &self.0
    }
}

impl UnlockingScript {
    /// Create from raw binary bytes.
    pub fn from_binary(bin: &[u8]) -> Self {
        UnlockingScript(Script::from_binary(bin))
    }

    /// Create from hex string.
    pub fn from_hex(hex: &str) -> Result<Self, crate::script::error::ScriptError> {
        Ok(UnlockingScript(Script::from_hex(hex)?))
    }

    /// Create from ASM string.
    pub fn from_asm(asm: &str) -> Self {
        UnlockingScript(Script::from_asm(asm))
    }

    /// Create from an existing Script.
    pub fn from_script(script: Script) -> Self {
        UnlockingScript(script)
    }
}
