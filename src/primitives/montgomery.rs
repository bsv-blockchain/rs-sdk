//! Montgomery multiplication context for efficient modular arithmetic.
//!
//! Montgomery multiplication provides an efficient method for modular
//! multiplication by transforming operands into Montgomery form, where
//! modular reduction is replaced by simple right-shifts.
//!
//! The CIOS (Coarsely Integrated Operand Scanning) algorithm performs
//! multiplication and reduction interleaved, avoiding the need for a
//! full-width product followed by division.

use crate::primitives::big_number::BigNumber;
use crate::primitives::reduction_context::ReductionContext;
use std::sync::Arc;

/// Montgomery reduction context for fast modular multiplication.
///
/// In Montgomery form, a value `a` is represented as `a * R mod m`,
/// where R = 2^(k*64) and k is the number of limbs in the modulus.
/// Multiplication of two Montgomery-form values followed by Montgomery
/// reduction is equivalent to modular multiplication.
#[derive(Debug)]
pub struct Montgomery {
    /// The modulus.
    pub m: BigNumber,
    /// The modulus as 4 limbs (for 256-bit moduli).
    pub m_limbs: [u64; 4],
    /// R = 2^(limb_count * 64).
    pub r: BigNumber,
    /// R^2 mod m (used for converting to Montgomery form).
    pub r2: BigNumber,
    /// R^2 mod m as 4 limbs.
    pub r2_limbs: [u64; 4],
    /// -m^(-1) mod 2^64 (used in reduction step).
    pub minv: u64,
    /// Number of limbs in the modulus.
    pub limb_count: usize,
}

/// Montgomery CIOS multiplication for 4-limb (256-bit) moduli.
///
/// Computes (a * b * R^(-1)) mod m where R = 2^256.
/// Uses the CIOS algorithm: for each limb of a, multiply-accumulate with b,
/// then perform a Montgomery reduction step.
///
/// All computation is on the stack -- no heap allocation.
#[inline]
pub fn mont_mul_4(a: &[u64; 4], b: &[u64; 4], m: &[u64; 4], m_inv: u64) -> [u64; 4] {
    // t has 5 limbs: 4 for the value + 1 for overflow
    let mut t = [0u64; 5];

    for &a_limb in a.iter().take(4) {
        // Step 1: t = t + a[i] * b
        let mut carry: u128 = 0;
        for j in 0..4 {
            let prod = (a_limb as u128) * (b[j] as u128) + (t[j] as u128) + carry;
            t[j] = prod as u64;
            carry = prod >> 64;
        }
        let sum = (t[4] as u128) + carry;
        t[4] = sum as u64;

        // Step 2: Montgomery reduction step
        // q = t[0] * m_inv mod 2^64
        let q = t[0].wrapping_mul(m_inv);

        // t = (t + q * m) >> 64
        carry = 0;
        for j in 0..4 {
            let prod = (q as u128) * (m[j] as u128) + (t[j] as u128) + carry;
            // We only need the carry; t[j] will be shifted
            if j > 0 {
                t[j - 1] = prod as u64;
            }
            // For j == 0: prod as u64 should be 0 by construction (t[0] + q*m[0] === 0 mod 2^64)
            carry = prod >> 64;
        }
        let sum = (t[4] as u128) + carry;
        t[3] = sum as u64;
        t[4] = (sum >> 64) as u64;
    }

    // Final conditional subtraction: if t >= m, subtract m
    let mut result = [t[0], t[1], t[2], t[3]];
    if t[4] > 0 || ge_4(&result, m) {
        sub_4_inplace(&mut result, m);
    }

    result
}

/// Montgomery squaring for 4-limb moduli. Delegates to mont_mul_4.
#[inline]
#[allow(dead_code)]
pub fn mont_sqr_4(a: &[u64; 4], m: &[u64; 4], m_inv: u64) -> [u64; 4] {
    mont_mul_4(a, a, m, m_inv)
}

/// Check if a >= b for 4-limb values.
#[inline(always)]
fn ge_4(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true // equal
}

/// Subtract b from a in place (4 limbs). Assumes a >= b.
#[inline(always)]
fn sub_4_inplace(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (d1, c1) = a[i].overflowing_sub(b[i]);
        let (d2, c2) = d1.overflowing_sub(borrow);
        a[i] = d2;
        borrow = (c1 as u64) + (c2 as u64);
    }
}

impl Montgomery {
    /// Create a new Montgomery context for the given modulus.
    /// The modulus must be odd (which all cryptographic primes are).
    pub fn new(m: &BigNumber) -> Self {
        let limb_count = m.bit_length().div_ceil(64);
        let bits = limb_count * 64;

        // R = 2^bits
        let r = BigNumber::one().ushln(bits);

        // R^2 mod m
        let r2 = r.sqr().umod(m).unwrap_or_else(|_| BigNumber::zero());

        // Extract modulus limbs
        let m_slice = m.get_limbs();
        let mut m_limbs = [0u64; 4];
        for (i, &v) in m_slice.iter().take(4).enumerate() {
            m_limbs[i] = v;
        }

        // Extract R^2 limbs
        let r2_slice = r2.get_limbs();
        let mut r2_limbs = [0u64; 4];
        for (i, &v) in r2_slice.iter().take(4).enumerate() {
            r2_limbs[i] = v;
        }

        // Compute -m^(-1) mod 2^64
        let m_low = m_limbs[0];
        let minv = compute_minv(m_low);

        Montgomery {
            m: m.clone(),
            m_limbs,
            r,
            r2,
            r2_limbs,
            minv,
            limb_count,
        }
    }

    /// Convert a BigNumber into Montgomery form: a_mont = a * R mod m.
    /// For 4-limb moduli, uses CIOS mont_mul_4 with R^2.
    pub fn to_mont(&self, a: &BigNumber) -> BigNumber {
        if self.limb_count == 4 {
            let a_slice = a.get_limbs();
            let mut a_limbs = [0u64; 4];
            for (i, &v) in a_slice.iter().take(4).enumerate() {
                a_limbs[i] = v;
            }
            let result = mont_mul_4(&a_limbs, &self.r2_limbs, &self.m_limbs, self.minv);
            return BigNumber::from_raw_limbs(&result);
        }
        // Fallback for non-4-limb moduli
        a.mul(&self.r2)
            .umod(&self.m)
            .unwrap_or_else(|_| BigNumber::zero())
    }

    /// Convert a BigNumber from Montgomery form: a = a_mont * R^(-1) mod m.
    /// For 4-limb moduli, uses CIOS with b = [1, 0, 0, 0].
    #[allow(clippy::wrong_self_convention)]
    pub fn from_mont(&self, a: &BigNumber) -> BigNumber {
        if self.limb_count == 4 {
            let a_slice = a.get_limbs();
            let mut a_limbs = [0u64; 4];
            for (i, &v) in a_slice.iter().take(4).enumerate() {
                a_limbs[i] = v;
            }
            let one = [1u64, 0, 0, 0];
            let result = mont_mul_4(&a_limbs, &one, &self.m_limbs, self.minv);
            return BigNumber::from_raw_limbs(&result);
        }
        // Fallback
        let r_inv = self.r.invm(&self.m).unwrap_or_else(|_| BigNumber::one());
        a.mul(&r_inv)
            .umod(&self.m)
            .unwrap_or_else(|_| BigNumber::zero())
    }

    /// Montgomery multiplication: (a * b * R^(-1)) mod m.
    /// For 4-limb moduli, uses CIOS directly.
    pub fn mul(&self, a: &BigNumber, b: &BigNumber) -> BigNumber {
        if self.limb_count == 4 {
            let a_slice = a.get_limbs();
            let b_slice = b.get_limbs();
            let mut a_limbs = [0u64; 4];
            let mut b_limbs = [0u64; 4];
            for (i, &v) in a_slice.iter().take(4).enumerate() {
                a_limbs[i] = v;
            }
            for (i, &v) in b_slice.iter().take(4).enumerate() {
                b_limbs[i] = v;
            }
            let result = mont_mul_4(&a_limbs, &b_limbs, &self.m_limbs, self.minv);
            return BigNumber::from_raw_limbs(&result);
        }
        let product = a.mul(b);
        self.reduce(&product)
    }

    /// Montgomery reduction: t * R^(-1) mod m.
    pub fn reduce(&self, t: &BigNumber) -> BigNumber {
        if self.limb_count == 4 {
            let t_slice = t.get_limbs();
            let mut t_limbs = [0u64; 4];
            for (i, &v) in t_slice.iter().take(4).enumerate() {
                t_limbs[i] = v;
            }
            let one = [1u64, 0, 0, 0];
            let result = mont_mul_4(&t_limbs, &one, &self.m_limbs, self.minv);
            return BigNumber::from_raw_limbs(&result);
        }
        let r_inv = self.r.invm(&self.m).unwrap_or_else(|_| BigNumber::one());
        t.mul(&r_inv)
            .umod(&self.m)
            .unwrap_or_else(|_| BigNumber::zero())
    }

    /// Create a ReductionContext backed by this Montgomery instance.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_reduction_context(self) -> Arc<ReductionContext> {
        ReductionContext::new(self.m)
    }
}

/// Compute -m^(-1) mod 2^64 using Newton's method.
/// Starting from m^(-1) mod 2, iterate: x = x * (2 - m * x) mod 2^k
/// doubling k each time until k = 64.
fn compute_minv(m_low: u64) -> u64 {
    if m_low == 0 {
        return 0;
    }

    // m must be odd for Montgomery to work
    // m^(-1) mod 2 = 1 (since m is odd)
    let mut x: u64 = 1;

    // Newton iterations: x = x * (2 - m * x) mod 2^64
    for _ in 0..6 {
        // 6 iterations: 2 -> 4 -> 8 -> 16 -> 32 -> 64 bits
        x = x.wrapping_mul(2u64.wrapping_sub(m_low.wrapping_mul(x)));
    }

    // We want -m^(-1) mod 2^64
    (0u64).wrapping_sub(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_montgomery_roundtrip() {
        let m = BigNumber::from_number(17);
        let mont = Montgomery::new(&m);

        let a = BigNumber::from_number(7);
        let a_mont = mont.to_mont(&a);
        let a_back = mont.from_mont(&a_mont);
        assert_eq!(a_back.to_number(), Some(7));
    }

    #[test]
    fn test_montgomery_mul() {
        let m = BigNumber::from_number(17);
        let mont = Montgomery::new(&m);

        let a = BigNumber::from_number(7);
        let b = BigNumber::from_number(5);

        let a_mont = mont.to_mont(&a);
        let b_mont = mont.to_mont(&b);
        let result_mont = mont.mul(&a_mont, &b_mont);
        let result = mont.from_mont(&result_mont);

        // 7 * 5 = 35 mod 17 = 1
        assert_eq!(result.to_number(), Some(1));
    }

    #[test]
    fn test_compute_minv() {
        // For m = 17 (odd), compute -17^(-1) mod 2^64
        let minv = compute_minv(17);
        // Verify: m * (-minv) === 1 (mod 2^64)
        let check = 17u64.wrapping_mul(minv);
        assert_eq!(check, u64::MAX); // -1 mod 2^64
    }
}
