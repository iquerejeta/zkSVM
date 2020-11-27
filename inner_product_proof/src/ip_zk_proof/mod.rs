#![allow(non_snake_case)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate rand;

use alloc::vec::Vec;

use core::iter;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, MultiscalarMul, VartimeMultiscalarMul};
use merlin::Transcript;

use crate::errors::ProofError;
use crate::generators::{BulletproofGens, PedersenGens};
use crate::inner_product_proof::InnerProductProof;
use crate::transcript::TranscriptProtocol;
use crate::util;

use rand_core::{CryptoRng, RngCore};
use serde::de::Visitor;
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};


/// The `RangeProof` struct represents a proof that one or more values
/// are in a range.
///
/// The `RangeProof` struct contains functions for creating and
/// verifying aggregated range proofs.  The single-value case is
/// implemented as a special case of aggregated range proofs.
///
/// The bitsize of the range, as well as the list of commitments to
/// the values, are not included in the proof, and must be known to
/// the verifier.
///
/// This implementation requires that both the bitsize `n` and the
/// aggregation size `m` be powers of two, so that `n = 8, 16, 32, 64`
/// and `m = 1, 2, 4, 8, 16, ...`.  Note that the aggregation size is
/// not given as an explicit parameter, but is determined by the
/// number of values or commitments passed to the prover or verifier.
///
/// # Note
///
/// For proving, these functions run the multiparty aggregation
/// protocol locally.  That API is exposed in the [`aggregation`](::range_proof_mpc)
/// module and can be used to perform online aggregation between
/// parties without revealing secret values to each other.
#[derive(Clone, Debug)]
pub struct InnerProductZKProof {
    /// Commitment to the bits of the value
    A: CompressedRistretto,
    /// Commitment to the blinding factors
    S: CompressedRistretto,
    /// Commitment to the \\(t_1\\) coefficient of \\( t(x) \\)
    T_1: CompressedRistretto,
    /// Commitment to the \\(t_2\\) coefficient of \\( t(x) \\)
    T_2: CompressedRistretto,
    /// Evaluation of the polynomial \\(t(x)\\) at the challenge point \\(x\\)
    t_x: Scalar,
    /// Blinding factor for the synthetic commitment to \\(t(x)\\)
    t_x_blinding: Scalar,
    /// Blinding factor for the synthetic commitment to the inner-product arguments
    e_blinding: Scalar,
    /// Proof data for the inner-product argument.
    ipp_proof: InnerProductProof,
}

impl InnerProductZKProof {
    /// Create a rangeproof for a given pair of value `v` and
    /// blinding scalar `v_blinding`.
    /// This is a convenience wrapper around [`RangeProof::prove_multiple`].

    pub fn prove_single<T: RngCore + CryptoRng>(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        transcript: &mut Transcript,
        v: Scalar,
        lhs_ip: &Vec<Scalar>,
        rhs_ip: &Vec<Scalar>,
        v_blinding: Scalar,
        a_blinding: Scalar,
        n: usize,
        rng: &mut T,
    ) -> Result<(InnerProductZKProof, CompressedRistretto), ProofError> {
        let V = pc_gens.commit(v.into(), v_blinding).compress();

        let A: RistrettoPoint = RistrettoPoint::multiscalar_mul(
            iter::once(&a_blinding).chain(lhs_ip.iter()).chain(rhs_ip.iter()),
            iter::once(&pc_gens.B_blinding)
                .chain(bp_gens.G(n, 1))
                .chain(bp_gens.H(n, 1))
        );

        let s_blinding = Scalar::random(rng);
        let s_L: Vec<Scalar> = (0..n).map(|_| Scalar::random(rng)).collect();
        let s_R: Vec<Scalar> = (0..n).map(|_| Scalar::random(rng)).collect();

        // Compute S = <s_L, G> + <s_R, H> + s_blinding * B_blinding
        let S = RistrettoPoint::multiscalar_mul(
            iter::once(&s_blinding).chain(s_L.iter()).chain(s_R.iter()),
            iter::once(&pc_gens.B_blinding)
                .chain(bp_gens.G(n, 1))
                .chain(bp_gens.H(n, 1))
        );

        // We already commit to the polynomials as well
        // Calculate t by calculating vectors l0, l1, r0, r1 and multiplying
        let mut l_poly = util::VecPoly1::zero(n);
        let mut r_poly = util::VecPoly1::zero(n);

        for i in 0..n {
            l_poly.0[i] = lhs_ip[i];
            l_poly.1[i] = s_L[i];
            r_poly.0[i] = rhs_ip[i];
            r_poly.1[i] = s_R[i];
        }

        let t_poly = l_poly.inner_product(&r_poly);

        // Generate x by committing to T_1, T_2 (line 49-54)
        let t_1_blinding = Scalar::random(rng);
        let t_2_blinding = Scalar::random(rng);
        let T_1 = pc_gens.commit(t_poly.1, t_1_blinding);
        let T_2 = pc_gens.commit(t_poly.2, t_2_blinding);

        transcript.append_point(b"V", &V);
        transcript.append_point(b"A", &A.compress());
        transcript.append_point(b"S", &S.compress());

        transcript.append_point(b"T_1", &T_1.compress());
        transcript.append_point(b"T_2", &T_2.compress());

        let x = transcript.challenge_scalar(b"x");

        let t_blinding_poly = util::Poly2(
            v_blinding,
            t_1_blinding,
            t_2_blinding,
        );

        let t_x = t_poly.eval(x);
        let t_x_blinding = t_blinding_poly.eval(x);
        let e_blinding = a_blinding + s_blinding * x;

        let l_vec = l_poly.eval(x);
        let r_vec = r_poly.eval(x);

        transcript.append_scalar(b"t_x", &t_x);
        transcript.append_scalar(b"t_x_blinding", &t_x_blinding);
        transcript.append_scalar(b"e_blinding", &e_blinding);

        // Get a challenge value to combine statements for the IPP
        let w = transcript.challenge_scalar(b"w");
        let Q = w * pc_gens.B;

        let G_factors: Vec<Scalar> = iter::repeat(Scalar::one()).take(n).collect();
        let H_factors: Vec<Scalar> = iter::repeat(Scalar::one()).take(n).collect();

        let G: Vec<RistrettoPoint> = bp_gens.G(n, 1).cloned().collect();
        let H: Vec<RistrettoPoint> = bp_gens.H(n, 1).cloned().collect();

        let ipp_proof = InnerProductProof::create(
            transcript,
            &Q,
            &G_factors,
            &H_factors,
            G.clone(),
            H.clone(),
            l_vec.clone(),
            r_vec.clone(),
        );

        let proof = InnerProductZKProof{
            A: A.compress(),
            S: S.compress(),
            T_1: T_1.compress(),
            T_2: T_2.compress(),
            t_x, t_x_blinding, e_blinding, ipp_proof};

        Ok((proof, V))
    }

    /// Verifies a rangeproof for a given value commitment \\(V\\).
    ///
    /// This is a convenience wrapper around `verify_multiple` for the `m=1` case.
    pub fn verify_single<T: RngCore + CryptoRng>(
        &self,
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        transcript: &mut Transcript,
        V: &CompressedRistretto,
        n: usize,
        rng: &mut T,
    ) -> Result<(), ProofError> {
//        self.verify_multiple_with_rng(bp_gens, pc_gens, transcript, &[*V], n, rng)
        transcript.append_point(b"V", V);
        transcript.validate_and_append_point(b"A", &self.A)?;
        transcript.validate_and_append_point(b"S", &self.S)?;

        transcript.validate_and_append_point(b"T_1", &self.T_1)?;
        transcript.validate_and_append_point(b"T_2", &self.T_2)?;

        let x = transcript.challenge_scalar(b"x");

        transcript.append_scalar(b"t_x", &self.t_x);
        transcript.append_scalar(b"t_x_blinding", &self.t_x_blinding);
        transcript.append_scalar(b"e_blinding", &self.e_blinding);

        let w = transcript.challenge_scalar(b"w");


        // Challenge value for batching statements to be verified
        let c = Scalar::random(rng);

        let (x_sq, x_inv_sq, s) = self.ipp_proof.verification_scalars(n, transcript)?;
        let s_inv = s.iter().rev();

        let a = self.ipp_proof.a;
        let b = self.ipp_proof.b;

        let g = s.iter().map(|s_i| - a * s_i);
        let h = s_inv.map(|s_i_inv| - b * s_i_inv);

        let basepoint_scalar = w * (self.t_x - a * b) + c * ( - self.t_x);

        let mega_check = RistrettoPoint::optional_multiscalar_mul(
            iter::once(Scalar::one())
                .chain(iter::once(x))
                .chain(iter::once(c * x))
                .chain(iter::once(c * x * x))
                .chain(x_sq.iter().cloned())
                .chain(x_inv_sq.iter().cloned())
                .chain(iter::once(-self.e_blinding - c * self.t_x_blinding))
                .chain(iter::once(basepoint_scalar))
                .chain(g)
                .chain(h)
                .chain(iter::once(c)),
            iter::once(self.A.decompress())
                .chain(iter::once(self.S.decompress()))
                .chain(iter::once(self.T_1.decompress()))
                .chain(iter::once(self.T_2.decompress()))
                .chain(self.ipp_proof.L_vec.iter().map(|L| L.decompress()))
                .chain(self.ipp_proof.R_vec.iter().map(|R| R.decompress()))
                .chain(iter::once(Some(pc_gens.B_blinding)))
                .chain(iter::once(Some(pc_gens.B)))
                .chain(bp_gens.G(n, 1).map(|&x| Some(x)))
                .chain(bp_gens.H(n, 1).map(|&x| Some(x)))
                .chain(iter::once(V.decompress())),
        )
            .ok_or_else(|| ProofError::VerificationError)?;

        if mega_check.is_identity() {
            Ok(())
        } else {
            Err(ProofError::VerificationError)
        }
    }

    /// Verify that S corresponds to an expected value of S
    pub fn verify_expected_A(&self, expected_A: CompressedRistretto) -> bool {
        self.A == expected_A
    }

    /// Serializes the proof into a byte array of \\(2 \lg n + 9\\)
    /// 32-byte elements, where \\(n\\) is the number of secret bits.
    ///
    /// # Layout
    ///
    /// The layout of the range proof encoding is:
    ///
    /// * four compressed Ristretto points \\(A,S,T_1,T_2\\),
    /// * three scalars \\(t_x, \tilde{t}_x, \tilde{e}\\),
    /// * \\(n\\) pairs of compressed Ristretto points \\(L_0,R_0\dots,L_{n-1},R_{n-1}\\),
    /// * two scalars \\(a, b\\).
    pub fn to_bytes(&self) -> Vec<u8> {
        // 7 elements: points A, S, T1, T2, scalars tx, tx_bl, e_bl.
        let mut buf = Vec::with_capacity(7 * 32 + self.ipp_proof.serialized_size());
        buf.extend_from_slice(self.A.as_bytes());
        buf.extend_from_slice(self.S.as_bytes());
        buf.extend_from_slice(self.T_1.as_bytes());
        buf.extend_from_slice(self.T_2.as_bytes());
        buf.extend_from_slice(self.t_x.as_bytes());
        buf.extend_from_slice(self.t_x_blinding.as_bytes());
        buf.extend_from_slice(self.e_blinding.as_bytes());
        buf.extend(self.ipp_proof.to_bytes_iter());
        buf
    }

    /// Deserializes the proof from a byte slice.
    ///
    /// Returns an error if the byte slice cannot be parsed into a `RangeProof`.
    pub fn from_bytes(slice: &[u8]) -> Result<InnerProductZKProof, ProofError> {
        if slice.len() % 32 != 0 {
            return Err(ProofError::FormatError);
        }
        if slice.len() < 7 * 32 {
            return Err(ProofError::FormatError);
        }

        use util::read32;

        let A = CompressedRistretto(read32(&slice[0 * 32..]));
        let S = CompressedRistretto(read32(&slice[1 * 32..]));
        let T_1 = CompressedRistretto(read32(&slice[2 * 32..]));
        let T_2 = CompressedRistretto(read32(&slice[3 * 32..]));

        let t_x = Scalar::from_canonical_bytes(read32(&slice[4 * 32..]))
            .ok_or(ProofError::FormatError)?;
        let t_x_blinding = Scalar::from_canonical_bytes(read32(&slice[5 * 32..]))
            .ok_or(ProofError::FormatError)?;
        let e_blinding = Scalar::from_canonical_bytes(read32(&slice[6 * 32..]))
            .ok_or(ProofError::FormatError)?;

        let ipp_proof = InnerProductProof::from_bytes(&slice[7 * 32..])?;

        Ok(InnerProductZKProof {
            A,
            S,
            T_1,
            T_2,
            t_x,
            t_x_blinding,
            e_blinding,
            ipp_proof,
        })
    }
    /// Computes an inner product of two vectors
    /// \\[
    ///    {\langle {\mathbf{a}}, {\mathbf{b}} \rangle} = \sum\_{i=0}^{n-1} a\_i \cdot b\_i.
    /// \\]
    /// Panics if the lengths of \\(\mathbf{a}\\) and \\(\mathbf{b}\\) are not equal.
    pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
        let mut out = Scalar::zero();
        if a.len() != b.len() {
            panic!("inner_product(a,b): lengths of vectors do not match");
        }
        for i in 0..a.len() {
            out += a[i] * b[i];
        }
        out
    }
}

impl Serialize for InnerProductZKProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}

impl<'de> Deserialize<'de> for InnerProductZKProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
    {
        struct RangeProofVisitor;

        impl<'de> Visitor<'de> for RangeProofVisitor {
            type Value = InnerProductZKProof;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("a valid RangeProof")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<InnerProductZKProof, E>
                where
                    E: serde::de::Error,
            {
                // Using Error::custom requires T: Display, which our error
                // type only implements when it implements std::error::Error.
                #[cfg(feature = "std")]
                    return InnerProductZKProof::from_bytes(v).map_err(serde::de::Error::custom);
                // In no-std contexts, drop the error message.
                #[cfg(not(feature = "std"))]
                    return InnerProductZKProof::from_bytes(v)
                    .map_err(|_| serde::de::Error::custom("deserialization error"));
            }
        }

        deserializer.deserialize_bytes(RangeProofVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::generators::PedersenGens;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::SeedableRng;

    use rand_chacha::ChaChaRng;

    fn single_ip_zk_proof_helper(n: usize) {
        let max_bitsize = 128;
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(max_bitsize, 1);
        let mut test_rng = ChaChaRng::from_seed([24u8; 32]);

        let (proof_bytes, value_commitments) = {

            let lhs_ip: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut test_rng)).collect();
            let rhs_ip: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut test_rng)).collect();
            let values: Scalar = InnerProductZKProof::inner_product(lhs_ip.as_slice(), rhs_ip.as_slice());

            let v_blinding: Scalar = Scalar::random(&mut test_rng);
            let a_blinding: Scalar = Scalar::random(&mut test_rng);

            // 1. Create the proof
            let mut transcript = Transcript::new(b"AggregatedRangeProofTest");
            let (proof, value_commitments) = InnerProductZKProof::prove_single(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                values,
                &lhs_ip,
                &rhs_ip,
                v_blinding,
                a_blinding,
                n,
                &mut test_rng
            )
                .unwrap();

            // 2. Return serialized proof and value commitments
            (bincode::serialize(&proof).unwrap(), value_commitments)
        };

        // Verifier's scope
        {
            // 3. Deserialize
            let proof: InnerProductZKProof = bincode::deserialize(&proof_bytes).unwrap();

            // 4. Verify with the same customization label as above
            let mut transcript = Transcript::new(b"AggregatedRangeProofTest");

            assert!(proof
                .verify_single(&bp_gens, &pc_gens, &mut transcript, &value_commitments, n, &mut test_rng)
                .is_ok());
        }
    }

    #[test]
    fn create_and_verify_ip_proof_8() {single_ip_zk_proof_helper(8);}

    #[test]
    fn create_and_verify_ip_proof_16() {single_ip_zk_proof_helper(16);}

    #[test]
    fn create_and_verify_ip_proof_32() {single_ip_zk_proof_helper(32);}

    #[test]
    fn create_and_verify_ip_proof_64() {single_ip_zk_proof_helper(64);}

    #[test]
    fn create_and_verify_ip_proof_128() {single_ip_zk_proof_helper(128);}
}