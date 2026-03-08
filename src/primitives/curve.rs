//! Elliptic curve parameters for secp256k1.
//!
//! The Curve struct holds the secp256k1 curve constants (p, a, b, n, G)
//! and provides a singleton instance via `Curve::secp256k1()`.

use crate::primitives::big_number::BigNumber;
use crate::primitives::point::Point;
use crate::primitives::reduction_context::ReductionContext;
use std::sync::Arc;

/// Represents the secp256k1 elliptic curve and its parameters.
///
/// secp256k1 is defined by y^2 = x^3 + 7 over GF(p) where:
/// - p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
/// - n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
/// - a = 0, b = 7
/// - G = (g_x, g_y) is the generator point
#[derive(Clone)]
pub struct Curve {
    /// Field prime p.
    pub p: BigNumber,
    /// Curve parameter a (= 0 for secp256k1).
    pub a: BigNumber,
    /// Curve parameter b (= 7 for secp256k1).
    pub b: BigNumber,
    /// Curve order n.
    pub n: BigNumber,
    /// Half of n, used for low-S checking.
    pub half_n: BigNumber,
    /// Generator point G (x coordinate).
    pub g_x: BigNumber,
    /// Generator point G (y coordinate).
    pub g_y: BigNumber,
    /// Reduction context for field arithmetic (mod p).
    pub red: Arc<ReductionContext>,
    /// Reduction context for scalar arithmetic (mod n).
    pub red_n: Arc<ReductionContext>,
    /// n mod p as a reduced BigNumber (for eqXToP checks).
    pub red_n_val: BigNumber,
    /// Bit length of the curve order.
    pub bit_length: usize,
}

/// Singleton Curve instance - lazily initialized.
static CURVE_INIT: std::sync::OnceLock<Curve> = std::sync::OnceLock::new();

impl Curve {
    /// Get the secp256k1 curve instance (singleton).
    pub fn secp256k1() -> &'static Curve {
        CURVE_INIT.get_or_init(|| {
            // SAFETY: all hex values below are hardcoded secp256k1 constants
            let p = BigNumber::from_hex(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            )
            .expect("valid hex for p");

            let n = BigNumber::from_hex(
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            )
            .expect("valid hex for n");

            let a = BigNumber::zero();
            let b = BigNumber::from_number(7);

            let g_x = BigNumber::from_hex(
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            )
            .expect("valid hex for G.x");

            let g_y = BigNumber::from_hex(
                "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            )
            .expect("valid hex for G.y");

            let half_n = n.ushrn(1);
            let bit_length = n.bit_length();

            let red = ReductionContext::k256();
            let red_n = ReductionContext::new(n.clone());

            // n mod p for eqXToP checks
            let red_n_val = n.umod(&p).unwrap_or_else(|_| BigNumber::zero());

            Curve {
                p,
                a,
                b,
                n,
                half_n,
                g_x,
                g_y,
                red,
                red_n,
                red_n_val,
                bit_length,
            }
        })
    }

    /// Get the generator point G as a Point.
    pub fn generator(&self) -> Point {
        Point::new(self.g_x.clone(), self.g_y.clone())
    }
}

impl std::fmt::Debug for Curve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Curve")
            .field("p", &self.p.to_hex())
            .field("n", &self.n.to_hex())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_curve_constants_p() {
        let curve = Curve::secp256k1();
        assert_eq!(
            curve.p.to_hex(),
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        );
    }

    #[test]
    fn test_curve_constants_n() {
        let curve = Curve::secp256k1();
        assert_eq!(
            curve.n.to_hex(),
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        );
    }

    #[test]
    fn test_curve_constants_a_b() {
        let curve = Curve::secp256k1();
        assert!(curve.a.is_zero());
        assert_eq!(curve.b.to_number(), Some(7));
    }

    #[test]
    fn test_curve_generator_x() {
        let curve = Curve::secp256k1();
        assert_eq!(
            curve.g_x.to_hex(),
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
    }

    #[test]
    fn test_curve_generator_y() {
        let curve = Curve::secp256k1();
        assert_eq!(
            curve.g_y.to_hex(),
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );
    }

    #[test]
    fn test_curve_half_n() {
        let curve = Curve::secp256k1();
        // half_n should be n >> 1
        let doubled = curve.half_n.add(&curve.half_n);
        // Since n is odd, doubled = n - 1
        let n_minus_1 = curve.n.subn(1);
        assert_eq!(doubled.cmp(&n_minus_1), 0);
    }

    #[test]
    fn test_curve_singleton() {
        let c1 = Curve::secp256k1();
        let c2 = Curve::secp256k1();
        // Same reference (singleton)
        assert_eq!(c1.p.to_hex(), c2.p.to_hex());
    }

    #[test]
    fn test_curve_g_on_curve() {
        // y^2 = x^3 + 7 (mod p)
        let curve = Curve::secp256k1();
        let x = curve.g_x.to_red(curve.red.clone());
        let y = curve.g_y.to_red(curve.red.clone());

        let y2 = curve.red.sqr(&y);
        let x3 = curve.red.mul(&x, &curve.red.sqr(&x));
        let seven = BigNumber::from_number(7).to_red(curve.red.clone());
        let rhs = curve.red.add(&x3, &seven);

        assert_eq!(y2.cmp(&rhs), 0);
    }

    #[test]
    fn test_curve_bit_length() {
        let curve = Curve::secp256k1();
        assert_eq!(curve.bit_length, 256);
    }
}
