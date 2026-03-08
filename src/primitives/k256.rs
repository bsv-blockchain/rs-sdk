//! K-256 (secp256k1) field reduction context.
//!
//! K256 implements fast modular reduction for the secp256k1 prime:
//! p = 2^256 - 2^32 - 977 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
//!
//! This prime has a special structure (pseudo-Mersenne) that allows reduction
//! without full division, using the identity: 2^256 = 2^32 + 977 (mod p).

use crate::primitives::big_number::BigNumber;
use crate::primitives::reduction_context::MersennePrime;

/// The secp256k1 prime p as 4 u64 limbs (little-endian).
/// p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
const P_LIMBS: [u64; 4] = [
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];

/// K = 2^256 - p = 0x1000003D1 (33 bits, fits in a single u64).
const K_VAL: u64 = 0x1000003D1;

/// K-256 field reduction context for secp256k1 prime modulus.
///
/// Exploits the structure p = 2^256 - 2^32 - 977 for fast reduction.
/// For a value v >= p, we split into hi * 2^256 + lo, then replace with
/// hi * (2^32 + 977) + lo, repeating until v < p.
#[derive(Debug)]
pub struct K256 {
    /// The prime p = 2^256 - 2^32 - 977.
    prime: BigNumber,
    /// k = 2^32 + 977 = 0x1000003d1
    k: BigNumber,
}

impl K256 {
    /// Create a new K256 reduction context.
    pub fn new() -> Self {
        // SAFETY: hardcoded constant hex values known to be valid
        let prime =
            BigNumber::from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
                .expect("K256 prime is valid hex");

        // k = 2^256 - p = 2^32 + 977 = 0x1000003d1
        // SAFETY: hardcoded constant hex value known to be valid
        let k = BigNumber::from_hex("1000003d1").expect("K256 k is valid hex");

        K256 { prime, k }
    }
}

impl Default for K256 {
    fn default() -> Self {
        Self::new()
    }
}

/// Reduce an 8-limb product modulo the secp256k1 prime, operating directly on limbs.
/// Input: 8 u64 limbs representing a 512-bit value (from 256-bit * 256-bit multiplication).
/// Output: 4 u64 limbs representing the result mod p.
///
/// Algorithm: split into hi (limbs[4..8]) and lo (limbs[0..4]).
/// result = hi * K + lo, where K = 0x1000003D1.
/// Since K is 33 bits and hi is 256 bits, hi*K is at most 289 bits,
/// so after adding lo we might need one more round.
#[inline]
pub fn k256_reduce_limbs(limbs: &[u64; 8]) -> [u64; 4] {
    // First round: hi * K + lo
    let mut acc = [0u64; 5]; // 5 limbs to hold potential overflow

    // Start with lo
    acc[0] = limbs[0];
    acc[1] = limbs[1];
    acc[2] = limbs[2];
    acc[3] = limbs[3];

    // Add hi * K (K fits in u64, so single-limb multiply)
    let mut carry: u128 = 0;
    for i in 0..4 {
        let prod = (limbs[i + 4] as u128) * (K_VAL as u128) + (acc[i] as u128) + carry;
        acc[i] = prod as u64;
        carry = prod >> 64;
    }
    acc[4] = carry as u64;

    // If acc[4] > 0, we have overflow past 256 bits -- do another round
    // acc[4] is at most ~33 bits, so acc[4] * K fits in u128 easily
    if acc[4] > 0 {
        let overflow = acc[4];
        acc[4] = 0;
        let mut c: u128 = (overflow as u128) * (K_VAL as u128) + (acc[0] as u128);
        acc[0] = c as u64;
        c >>= 64;
        if c > 0 {
            for item in acc.iter_mut().take(4).skip(1) {
                c += *item as u128;
                *item = c as u64;
                c >>= 64;
                if c == 0 {
                    break;
                }
            }
        }
    }

    let mut result = [acc[0], acc[1], acc[2], acc[3]];

    // Final conditional subtraction: if result >= p, subtract p
    if ge_p(&result) {
        sub_p_inplace(&mut result);
    }

    result
}

/// Check if a 4-limb value >= p (secp256k1 prime).
#[inline(always)]
fn ge_p(a: &[u64; 4]) -> bool {
    // Compare from most significant limb
    for i in (0..4).rev() {
        if a[i] > P_LIMBS[i] {
            return true;
        }
        if a[i] < P_LIMBS[i] {
            return false;
        }
    }
    true // equal
}

/// Subtract p from a 4-limb value in place.
#[inline(always)]
fn sub_p_inplace(a: &mut [u64; 4]) {
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (d1, c1) = a[i].overflowing_sub(P_LIMBS[i]);
        let (d2, c2) = d1.overflowing_sub(borrow);
        a[i] = d2;
        borrow = (c1 as u64) + (c2 as u64);
    }
}

impl MersennePrime for K256 {
    fn ireduce(&self, num: &mut BigNumber) {
        let limbs = num.get_limbs();

        // Fast path: 8-limb input (result of 4-limb * 4-limb multiplication)
        if limbs.len() == 8 {
            let input: [u64; 8] = [
                limbs[0], limbs[1], limbs[2], limbs[3], limbs[4], limbs[5], limbs[6], limbs[7],
            ];
            let result = k256_reduce_limbs(&input);
            *num = BigNumber::from_raw_limbs(&result);
            return;
        }

        // Fast path: already <= 4 limbs (256 bits or less)
        if limbs.len() <= 4 {
            // Just check if >= p and subtract
            if limbs.len() == 4 {
                let a: [u64; 4] = [limbs[0], limbs[1], limbs[2], limbs[3]];
                if ge_p(&a) {
                    let mut r = a;
                    sub_p_inplace(&mut r);
                    *num = BigNumber::from_raw_limbs(&r);
                }
            }
            return;
        }

        // Fallback for other sizes: use the generic BigNumber approach
        loop {
            if num.bit_length() <= 256 {
                break;
            }

            let hi = num.ushrn(256);
            let lo = num.maskn(256);
            let hi_k = hi.mul(&self.k);
            *num = hi_k.add(&lo);
        }

        let cmp = num.ucmp(&self.prime);
        if cmp == 0 {
            *num = BigNumber::zero();
        } else if cmp > 0 {
            *num = num.sub(&self.prime);
        }
    }

    fn p(&self) -> &BigNumber {
        &self.prime
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_k256_reduce_within_range() {
        let k = K256::new();
        let mut n = BigNumber::from_number(42);
        k.ireduce(&mut n);
        assert_eq!(n.to_number(), Some(42));
    }

    #[test]
    fn test_k256_reduce_at_p() {
        let k = K256::new();
        let mut n =
            BigNumber::from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
                .unwrap();
        k.ireduce(&mut n);
        assert!(n.is_zero());
    }

    #[test]
    fn test_k256_reduce_p_plus_1() {
        let k = K256::new();
        let mut n =
            BigNumber::from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30")
                .unwrap();
        k.ireduce(&mut n);
        assert_eq!(n.to_number(), Some(1));
    }

    #[test]
    fn test_k256_reduce_large_value() {
        let k = K256::new();
        // A 512-bit value
        let mut n = BigNumber::from_hex(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f\
             fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        )
        .unwrap();
        k.ireduce(&mut n);
        // Result should be < p
        assert!(n.ucmp(&k.prime) < 0);
        assert!(n.bit_length() <= 256);
    }
}
