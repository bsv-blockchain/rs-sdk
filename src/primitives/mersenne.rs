//! Mersenne prime reduction for efficient modular arithmetic.
//!
//! A pseudo-Mersenne prime has the form p = 2^n - k, where n and k are
//! integers. For such primes, modular reduction can exploit the identity
//! 2^n = k (mod p) to avoid full division.

use crate::primitives::big_number::BigNumber;
use crate::primitives::reduction_context::MersennePrime;

/// Mersenne prime reduction context.
///
/// Stores a pseudo-Mersenne prime p = 2^n - k and uses the structure
/// to perform fast modular reduction via the split-and-multiply technique.
#[derive(Debug)]
pub struct Mersenne {
    /// Name identifier for this prime.
    pub name: String,
    /// The prime p = 2^n - k.
    pub prime: BigNumber,
    /// k = 2^n - p (the small correction factor).
    pub k: BigNumber,
    /// n = bit_length(p).
    pub n: usize,
}

impl Mersenne {
    /// Create a new Mersenne context from a hex string for the prime.
    pub fn new(name: &str, p_hex: &str) -> Result<Self, crate::primitives::PrimitivesError> {
        // Remove spaces from hex string
        let hex_clean: String = p_hex.chars().filter(|c| !c.is_whitespace()).collect();
        let prime = BigNumber::from_hex(&hex_clean)?;
        let n = prime.bit_length();

        // k = 2^n - p
        let two_n = BigNumber::one().ushln(n);
        let k = two_n.sub(&prime);

        Ok(Mersenne {
            name: name.to_string(),
            prime,
            k,
            n,
        })
    }
}

impl MersennePrime for Mersenne {
    fn ireduce(&self, num: &mut BigNumber) {
        // num = hi * 2^n + lo = hi * k + lo (mod p)
        loop {
            if num.bit_length() <= self.n {
                break;
            }

            // hi = num >> n
            let hi = num.ushrn(self.n);
            // lo = num & (2^n - 1)
            let lo = num.maskn(self.n);

            // num = hi * k + lo
            let hi_k = hi.mul(&self.k);
            *num = hi_k.add(&lo);
        }

        // Final comparison
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
    fn test_mersenne_basic() {
        // M31: 2^31 - 1 = 2147483647
        let m = Mersenne::new("M31", "7fffffff").unwrap();
        assert_eq!(m.n, 31);
        assert_eq!(m.k.to_number(), Some(1)); // k = 2^31 - (2^31 - 1) = 1
    }

    #[test]
    fn test_mersenne_reduce() {
        let m = Mersenne::new("M31", "7fffffff").unwrap();
        let mut n = BigNumber::from_hex("80000000").unwrap(); // 2^31
        m.ireduce(&mut n);
        assert_eq!(n.to_number(), Some(1)); // 2^31 mod (2^31-1) = 1
    }

    #[test]
    fn test_mersenne_reduce_within_range() {
        let m = Mersenne::new("M31", "7fffffff").unwrap();
        let mut n = BigNumber::from_number(42);
        m.ireduce(&mut n);
        assert_eq!(n.to_number(), Some(42));
    }
}
