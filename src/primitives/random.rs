//! Cryptographically secure random byte generation.
//!
//! With the `std` feature this uses the `getrandom` crate, which delegates to
//! the platform CSPRNG (`/dev/urandom` on Linux, `SecRandomCopyBytes` on macOS,
//! `BCryptGenRandom` on Windows, `crypto.getRandomValues` when `wasm-js` is
//! enabled).
//!
//! Without `std` there is no OS entropy source. Install one with
//! [`set_rng_hook`] before calling [`random_bytes`] — for example the Ledger
//! `cx_rng` syscall.

use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
mod hook {
    use core::sync::atomic::{AtomicPtr, Ordering};

    pub type RngHook = fn(&mut [u8]) -> Result<(), &'static str>;

    static RNG_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

    pub fn set(hook: RngHook) {
        RNG_HOOK.store(hook as *mut (), Ordering::Release);
    }

    pub fn get() -> Option<RngHook> {
        let ptr = RNG_HOOK.load(Ordering::Acquire);
        if ptr.is_null() {
            None
        } else {
            // SAFETY: `set` only stores a `RngHook` function pointer, and the
            // pointer is not freed. Transmuting it back yields that same hook.
            Some(unsafe { core::mem::transmute::<*mut (), RngHook>(ptr) })
        }
    }
}

/// Install the CSPRNG used by [`random_bytes`] when the `std` feature is off.
///
/// `hook` must fill the entire buffer from a cryptographic RNG and return
/// `Ok(())`, or `Err` with a static message. Replacing the hook is atomic.
/// On `std` builds `getrandom` is used and this function is not available.
#[cfg(not(feature = "std"))]
pub fn set_rng_hook(hook: fn(&mut [u8]) -> Result<(), &'static str>) {
    hook::set(hook);
}

/// Generate `len` cryptographically secure random bytes.
///
/// Returns an empty Vec if `len` is 0.
///
/// # Panics
///
/// On `std`, panics if the OS random number generator fails, which should
/// only happen in extremely unusual circumstances (for example very early
/// boot with no entropy). Without `std`, panics if no hook has been installed
/// via [`set_rng_hook`] or if the hook returns an error.
pub fn random_bytes(len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    let mut buf = alloc::vec![0u8; len];
    fill_random(&mut buf);
    buf
}

#[cfg(feature = "std")]
fn fill_random(buf: &mut [u8]) {
    // OS CSPRNG failure is unrecoverable (no entropy source available).
    getrandom::getrandom(buf).expect("OS random number generator failed");
}

#[cfg(not(feature = "std"))]
fn fill_random(buf: &mut [u8]) {
    let hook = hook::get().expect(
        "no RNG hook installed; call bsv::primitives::random::set_rng_hook before random_bytes",
    );
    hook(buf).expect("RNG hook failed");
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes_correct_length() {
        assert_eq!(random_bytes(0).len(), 0);
        assert_eq!(random_bytes(1).len(), 1);
        assert_eq!(random_bytes(32).len(), 32);
        assert_eq!(random_bytes(64).len(), 64);
        assert_eq!(random_bytes(256).len(), 256);
    }

    #[test]
    fn test_random_bytes_empty() {
        let result = random_bytes(0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_random_bytes_varying_output() {
        // Two consecutive calls should produce different output
        // (probability of collision for 32 bytes is negligible: 2^-256)
        let a = random_bytes(32);
        let b = random_bytes(32);
        assert_ne!(
            a, b,
            "Two random_bytes(32) calls should produce different output"
        );
    }

    #[test]
    fn test_random_bytes_non_zero() {
        // 64 random bytes should not all be zero
        // (probability: 2^-512, effectively impossible)
        let result = random_bytes(64);
        assert!(
            result.iter().any(|&b| b != 0),
            "64 random bytes should not all be zero"
        );
    }

    #[test]
    fn test_random_bytes_distribution() {
        // Generate a large sample and verify it's not degenerate
        // (all same byte value would indicate a broken RNG)
        let result = random_bytes(1024);
        let first = result[0];
        let all_same = result.iter().all(|&b| b == first);
        assert!(
            !all_same,
            "1024 random bytes should not all be the same value"
        );
    }
}
