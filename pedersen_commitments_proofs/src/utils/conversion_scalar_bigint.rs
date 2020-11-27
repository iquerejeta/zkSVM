use curve25519_dalek::scalar::Scalar;
use num_bigint::{BigInt, Sign};
use std::ops::Neg;

pub fn scalar_to_bigInt(scalar: &Scalar) -> BigInt {
    let bytes = scalar.to_bytes();

    BigInt::from_bytes_le(Sign::Plus, &bytes)
}

pub fn bigInt_to_scalar(bigInt: &BigInt) -> Result<Scalar, &'static str> {
    let mut buf = [0u8; 64];
    let bytes = bigInt.to_bytes_le();
    if bytes.1.len() > 64 {
        return Err("Size of BigInt bigger than expected.");
    }

    for (index, &value) in bytes.1.iter().enumerate() {
        buf[index] = value;
    }

    if bigInt.sign() == Sign::Plus {
        return Ok(Scalar::from_bytes_mod_order_wide(&buf))
    }

    else {
        return Ok(Scalar::from_bytes_mod_order_wide(&buf).neg())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversion() {
        let scalar18: Scalar = Scalar::from(17u8);
        let big_int18: BigInt = BigInt::from(17u64);

        let converted_scalar = scalar_to_bigInt(&scalar18);
        let converted_big_int = bigInt_to_scalar(&big_int18).unwrap();

        assert_eq!(scalar18, converted_big_int);
        assert_eq!(big_int18, converted_scalar);

        let returned_scalar: Scalar = bigInt_to_scalar(&converted_scalar).unwrap();
        let returned_big_int: BigInt = scalar_to_bigInt(&converted_big_int);

        assert_eq!(scalar18, returned_scalar);
        assert_eq!(big_int18, returned_big_int);
    }

    #[test]
    fn test_neg_conversion() {
        let scalar18: Scalar = Scalar::from(17u8).neg();
        let big_int18: BigInt = BigInt::from(17u64).neg();

        let converted_big_int = bigInt_to_scalar(&big_int18).unwrap();

        assert_eq!(scalar18, converted_big_int);
    }
}