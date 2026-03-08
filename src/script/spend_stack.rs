//! Stack operations for the Spend interpreter with memory tracking.
//!
//! All stack methods are defined as methods on Spend so they can access
//! the stack, alt_stack, and memory tracking fields directly.

use crate::script::error::ScriptError;
use crate::script::spend::Spend;

impl Spend {
    /// Push an item onto the main stack, tracking memory usage.
    pub(crate) fn push_stack(&mut self, item: Vec<u8>) -> Result<(), ScriptError> {
        self.ensure_stack_mem(item.len())?;
        self.stack_mem += item.len();
        self.stack.push(item);
        Ok(())
    }

    /// Pop an item from the main stack, adjusting memory tracking.
    pub(crate) fn pop_stack(&mut self) -> Result<Vec<u8>, ScriptError> {
        match self.stack.pop() {
            Some(item) => {
                self.stack_mem = self.stack_mem.saturating_sub(item.len());
                Ok(item)
            }
            None => Err(ScriptError::StackUnderflow),
        }
    }

    /// Peek at a stack item by offset from top. offset=0 is top, offset=1 is second-from-top, etc.
    pub(crate) fn stack_top(&self, offset: isize) -> Result<&Vec<u8>, ScriptError> {
        let idx = self.stack.len() as isize - 1 - offset;
        if idx < 0 || idx >= self.stack.len() as isize {
            return Err(ScriptError::InvalidStackOperation(format!(
                "stack_top offset {} out of range (stack size {})",
                offset,
                self.stack.len()
            )));
        }
        Ok(&self.stack[idx as usize])
    }

    /// Mutable peek at a stack item by offset from top.
    #[allow(dead_code)]
    pub(crate) fn stack_top_mut(&mut self, offset: isize) -> Result<&mut Vec<u8>, ScriptError> {
        let len = self.stack.len() as isize;
        let idx = len - 1 - offset;
        if idx < 0 || idx >= len {
            return Err(ScriptError::InvalidStackOperation(format!(
                "stack_top_mut offset {} out of range (stack size {})",
                offset,
                self.stack.len()
            )));
        }
        Ok(&mut self.stack[idx as usize])
    }

    /// Push an item onto the alt stack, tracking memory.
    pub(crate) fn push_alt_stack(&mut self, item: Vec<u8>) -> Result<(), ScriptError> {
        self.ensure_stack_mem(item.len())?;
        self.alt_stack_mem += item.len();
        self.alt_stack.push(item);
        Ok(())
    }

    /// Pop an item from the alt stack.
    pub(crate) fn pop_alt_stack(&mut self) -> Result<Vec<u8>, ScriptError> {
        match self.alt_stack.pop() {
            Some(item) => {
                self.alt_stack_mem = self.alt_stack_mem.saturating_sub(item.len());
                Ok(item)
            }
            None => Err(ScriptError::InvalidStackOperation(
                "alt stack empty".to_string(),
            )),
        }
    }

    /// Convert a stack item to a boolean.
    ///
    /// Bitcoin boolean: true if any byte is non-zero, except negative zero
    /// (0x80 in the last byte with all others zero) which is false.
    pub(crate) fn stack_to_bool(item: &[u8]) -> bool {
        if item.is_empty() {
            return false;
        }
        for (i, &byte) in item.iter().enumerate() {
            if byte != 0 {
                // Negative zero: last byte is 0x80, all others zero
                if i == item.len() - 1 && byte == 0x80 {
                    return false;
                }
                return true;
            }
        }
        false
    }

    /// Convert a boolean to a stack item.
    pub(crate) fn bool_to_stack(b: bool) -> Vec<u8> {
        if b {
            vec![1]
        } else {
            vec![]
        }
    }

    /// Check that adding `additional` bytes would not exceed the memory limit.
    pub(crate) fn ensure_stack_mem(&self, additional: usize) -> Result<(), ScriptError> {
        let total = self.stack_mem + self.alt_stack_mem + additional;
        if total > self.memory_limit {
            return Err(ScriptError::MemoryLimitExceeded);
        }
        Ok(())
    }
}
