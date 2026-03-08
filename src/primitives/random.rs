//! Cryptographically secure random byte generation.
//!
//! Uses the `getrandom` crate for OS-provided entropy, which delegates
//! to the appropriate platform-specific CSPRNG (e.g., /dev/urandom on
//! Linux, SecRandomCopyBytes on macOS, BCryptGenRandom on Windows).

/// Generate `len` cryptographically secure random bytes.
///
/// Uses the operating system's CSPRNG via the `getrandom` crate.
/// Returns an empty Vec if `len` is 0.
///
/// # Panics
///
/// Panics if the OS random number generator fails, which should
/// only happen in extremely unusual circumstances (e.g., very early
/// boot on a system with no entropy sources).
pub fn random_bytes(len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    let mut buf = vec![0u8; len];
    // SAFETY: OS CSPRNG failure is unrecoverable (no entropy source available)
    getrandom::getrandom(&mut buf).expect("OS random number generator failed");
    buf
}

#[cfg(test)]
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
