//! Modular reduction context for field arithmetic.
//!
//! ReductionContext provides modular arithmetic operations (add, sub, mul, sqr,
//! invm, pow, sqrt) over BigNumber values under a given modulus. This is used
//! for secp256k1 field and scalar arithmetic.

use crate::primitives::big_number::BigNumber;
use crate::primitives::k256::k256_reduce_limbs;
use crate::primitives::montgomery::Montgomery;
use std::sync::Arc;

/// Context for performing modular reduction operations.
///
/// Mirrors the TS SDK's ReductionContext class. Can be constructed with an
/// arbitrary modulus or with the string "k256" to use the secp256k1 prime.
#[derive(Debug)]
pub struct ReductionContext {
    /// The modulus used for reduction.
    pub m: BigNumber,
    /// Optional Mersenne prime for fast reduction.
    prime: Option<Box<dyn MersennePrime>>,
    /// Optional Montgomery context for the modulus (available for K256).
    pub mont: Option<Montgomery>,
}

/// Trait for Mersenne-like prime reduction (used by K256).
pub trait MersennePrime: std::fmt::Debug + Send + Sync {
    /// Reduce a BigNumber in-place using the Mersenne prime structure.
    fn ireduce(&self, num: &mut BigNumber);
    /// The prime value.
    fn p(&self) -> &BigNumber;
}

impl ReductionContext {
    /// Create a new ReductionContext with the given modulus.
    pub fn new(m: BigNumber) -> Arc<Self> {
        Arc::new(ReductionContext {
            m,
            prime: None,
            mont: None,
        })
    }

    /// Create a ReductionContext for the secp256k1 field prime (k256).
    /// Includes a Montgomery context for use by callers needing Montgomery form.
    pub fn k256() -> Arc<Self> {
        let k = crate::primitives::k256::K256::new();
        let m = k.p().clone();
        let mont = Montgomery::new(&m);
        Arc::new(ReductionContext {
            m,
            prime: Some(Box::new(k)),
            mont: Some(mont),
        })
    }

    /// Create a new ReductionContext with a Mersenne prime.
    pub fn with_prime(prime: Box<dyn MersennePrime>) -> Arc<Self> {
        let m = prime.p().clone();
        Arc::new(ReductionContext {
            m,
            prime: Some(prime),
            mont: None,
        })
    }

    /// Reduce a BigNumber modulo m.
    pub fn imod(&self, a: &BigNumber) -> BigNumber {
        if let Some(ref prime) = self.prime {
            let mut r = a.clone();
            prime.ireduce(&mut r);
            r
        } else {
            a.umod(&self.m).unwrap_or_else(|_| BigNumber::zero())
        }
    }

    /// Convert a BigNumber into this reduction context (reduce mod m).
    pub fn convert_to(&self, num: &BigNumber) -> BigNumber {
        num.umod(&self.m).unwrap_or_else(|_| BigNumber::zero())
    }

    /// Convert a BigNumber from this reduction context (just clone).
    pub fn convert_from(&self, num: &BigNumber) -> BigNumber {
        let mut r = num.clone();
        r.red = None;
        r
    }

    /// Negate a in the context of modulus m.
    pub fn neg(&self, a: &BigNumber) -> BigNumber {
        if a.is_zero() {
            return a.clone();
        }
        self.m.sub(a)
    }

    /// Add two BigNumbers mod m.
    pub fn add(&self, a: &BigNumber, b: &BigNumber) -> BigNumber {
        let mut res = a.add(b);
        res = res.sub(&self.m);
        if res.is_neg() {
            res = res.add(&self.m);
        }
        // Preserve red context
        res.red = a.red.clone();
        res
    }

    /// Subtract b from a mod m.
    pub fn sub(&self, a: &BigNumber, b: &BigNumber) -> BigNumber {
        let mut res = a.sub(b);
        if res.is_neg() {
            res = res.add(&self.m);
        }
        res.red = a.red.clone();
        res
    }

    /// Multiply two BigNumbers mod m.
    /// For K256 with 4-limb operands, uses Karatsuba mul_4x4 followed by
    /// limb-level K256 reduction, avoiding all BigNumber temporary allocations.
    pub fn mul(&self, a: &BigNumber, b: &BigNumber) -> BigNumber {
        // Fast path: 4-limb K256 -- bypass all BigNumber intermediates
        let a_limbs = a.get_limbs();
        let b_limbs = b.get_limbs();
        if self.prime.is_some() && a_limbs.len() == 4 && b_limbs.len() == 4 {
            let a4: [u64; 4] = [a_limbs[0], a_limbs[1], a_limbs[2], a_limbs[3]];
            let b4: [u64; 4] = [b_limbs[0], b_limbs[1], b_limbs[2], b_limbs[3]];
            let prod8 = crate::primitives::big_number::mul_4x4(&a4, &b4);
            let reduced = k256_reduce_limbs(&prod8);
            let mut result = BigNumber::from_raw_limbs(&reduced);
            result.red = a.red.clone();
            return result;
        }

        let prod = a.mul(b);
        let mut result = self.imod(&prod);
        result.red = a.red.clone();
        result
    }

    /// Square a BigNumber mod m.
    /// For K256 with 4-limb operands, uses sqr_4x4 followed by
    /// limb-level K256 reduction.
    pub fn sqr(&self, a: &BigNumber) -> BigNumber {
        // Fast path: 4-limb K256 -- bypass all BigNumber intermediates
        let a_limbs = a.get_limbs();
        if self.prime.is_some() && a_limbs.len() == 4 {
            let a4: [u64; 4] = [a_limbs[0], a_limbs[1], a_limbs[2], a_limbs[3]];
            let prod8 = crate::primitives::big_number::mul_4x4(&a4, &a4);
            let reduced = k256_reduce_limbs(&prod8);
            let mut result = BigNumber::from_raw_limbs(&reduced);
            result.red = a.red.clone();
            return result;
        }

        let sq = a.sqr();
        let mut result = self.imod(&sq);
        result.red = a.red.clone();
        result
    }

    /// Modular inverse in context.
    pub fn invm(&self, a: &BigNumber) -> BigNumber {
        let inv = a.invm(&self.m).unwrap_or_else(|_| BigNumber::zero());
        let mut result = self.imod(&inv);
        result.red = a.red.clone();
        result
    }

    /// Modular exponentiation: a^exp mod m.
    pub fn pow(&self, a: &BigNumber, exp: &BigNumber) -> BigNumber {
        if exp.is_zero() {
            let mut one = BigNumber::one();
            one.red = a.red.clone();
            return one;
        }

        let mut result = BigNumber::one();
        result.red = a.red.clone();
        let base = a.clone();
        let bits = exp.bit_length();

        for i in (0..bits).rev() {
            result = self.sqr(&result);
            if exp.testn(i) {
                result = self.mul(&result, &base);
            }
        }

        result
    }

    /// Modular square root (Tonelli-Shanks for p % 4 == 3).
    pub fn sqrt(&self, a: &BigNumber) -> BigNumber {
        if a.is_zero() {
            return a.clone();
        }

        let mod4 = self.m.andln(2);
        // p % 4 == 3 fast path: sqrt(a) = a^((p+1)/4) mod p
        if mod4 != 0 {
            let exp = self.m.addn(1);
            let exp = exp.ushrn(2);
            return self.pow(a, &exp);
        }

        // Tonelli-Shanks for general case
        let mut q = self.m.subn(1);
        let mut s = 0usize;
        while !q.is_zero() && q.andln(1) == 0 {
            s += 1;
            q.iushrn(1);
        }

        let one = BigNumber::one();
        let one_red = {
            let mut o = one.clone();
            o.red = a.red.clone();
            o
        };
        let neg_one = self.neg(&one_red);

        // Find quadratic non-residue z
        let lpow = self.m.subn(1).ushrn(1);
        let zl = self.m.bit_length();
        let mut z = BigNumber::from_number(2 * (zl * zl) as i64);
        z.red = a.red.clone();

        while self.pow(&z, &lpow).cmp(&neg_one) != 0 {
            let neg_one_clone = neg_one.clone();
            z = self.add(&z, &neg_one_clone);
        }

        let mut c = self.pow(&z, &q);
        let mut r = self.pow(a, &q.addn(1).ushrn(1));
        let mut t = self.pow(a, &q);
        let mut m = s;

        while t.cmp(&one_red) != 0 {
            let mut tmp = t.clone();
            let mut i = 0;
            while tmp.cmp(&one_red) != 0 {
                tmp = self.sqr(&tmp);
                i += 1;
            }

            let mut shift = BigNumber::one();
            shift.iushln(m - i - 1);
            let b = self.pow(&c, &shift);

            r = self.mul(&r, &b);
            c = self.sqr(&b);
            t = self.mul(&t, &c);
            m = i;
        }

        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reduction_context_basic() {
        let ctx = ReductionContext::new(BigNumber::from_number(7));
        let a = BigNumber::from_number(10);
        let result = ctx.imod(&a);
        assert_eq!(result.to_number(), Some(3)); // 10 mod 7 = 3
    }

    #[test]
    fn test_reduction_context_add() {
        let ctx = ReductionContext::new(BigNumber::from_number(7));
        let a = BigNumber::from_number(5);
        let b = BigNumber::from_number(4);
        let result = ctx.add(&a, &b);
        assert_eq!(result.to_number(), Some(2)); // (5 + 4) mod 7 = 2
    }

    #[test]
    fn test_reduction_context_sub() {
        let ctx = ReductionContext::new(BigNumber::from_number(7));
        let a = BigNumber::from_number(3);
        let b = BigNumber::from_number(5);
        let result = ctx.sub(&a, &b);
        assert_eq!(result.to_number(), Some(5)); // (3 - 5) mod 7 = 5
    }

    #[test]
    fn test_reduction_context_mul() {
        let ctx = ReductionContext::new(BigNumber::from_number(7));
        let a = BigNumber::from_number(3);
        let b = BigNumber::from_number(4);
        let result = ctx.mul(&a, &b);
        assert_eq!(result.to_number(), Some(5)); // (3 * 4) mod 7 = 5
    }

    #[test]
    fn test_reduction_context_invm() {
        let ctx = ReductionContext::new(BigNumber::from_number(11));
        let a = BigNumber::from_number(3);
        let inv = ctx.invm(&a);
        // 3 * inv mod 11 should be 1
        let check = ctx.mul(&a, &inv);
        assert_eq!(check.to_number(), Some(1));
    }

    #[test]
    fn test_reduction_context_pow() {
        let ctx = ReductionContext::new(BigNumber::from_number(7));
        let a = BigNumber::from_number(3);
        let exp = BigNumber::from_number(2);
        let result = ctx.pow(&a, &exp);
        assert_eq!(result.to_number(), Some(2)); // 3^2 mod 7 = 2
    }
}
