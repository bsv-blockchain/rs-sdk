//! Script engine: opcodes, script types, locking/unlocking scripts, and evaluation.

#![allow(clippy::module_inception)]

pub mod address;
pub mod bip276;
pub mod error;
pub mod inscriptions;
pub mod locking_script;
pub mod op;
pub mod script;
pub mod script_chunk;
pub mod unlocking_script;

pub mod spend;
pub(crate) mod spend_ops;
pub(crate) mod spend_stack;
pub mod templates;

pub use templates::{ScriptTemplateLock, ScriptTemplateUnlock};

pub use address::Address;
pub use error::ScriptError;
pub use locking_script::LockingScript;
pub use op::Op;
pub use script::Script;
pub use script_chunk::ScriptChunk;
pub use spend::{Spend, SpendParams};
pub use unlocking_script::UnlockingScript;
