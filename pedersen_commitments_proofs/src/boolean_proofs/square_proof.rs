#![allow(non_snake_case)]
use curve25519_dalek::ristretto::{CompressedRistretto};
use curve25519_dalek::scalar::Scalar;

use ip_zk_proof::{BulletproofGens, PedersenGens, RangeProof, ProofError};

use merlin::Transcript;
use std::convert::TryInto;

use crate::boolean_proofs::equality_proof::EqualityZKProof;
use crate::generators::PedersenVecGens;
use rand::thread_rng;

#[derive(Clone)]
// Given that we are working on a finite field, if the square root of a number is not an integer,
// the proof below is not of great help. If we want to calculate the floor rounding of a square
// root, we need to complicate it one step further.
// Having the square, and its floored square root, what we do to compute a proof of floored square
// root relation, is:
//  - prove that we have a commitment of the square of the floored square root
//  - prove that this commitment hides a number smaller than the commitment of the original square
//  - prove that we have a commitment of the square of the floored square root plus one
//  - prove that this commitment hides a number greater than the commitment of the original square
// This suffices to prove that the number we are using is the nearest lower integer of the square
// root of the original square
pub struct FloatingSquareZKProof {
    commitment_round_square_p1: CompressedRistretto,
    leq_1: RangeProof,
    leq_2: RangeProof,
    square_zk_1: SquareZKProof,
    square_zk_2: SquareZKProof,
}

impl FloatingSquareZKProof {
    pub fn create(
        bulletproof_generators: &BulletproofGens,
        pedersen_generators: PedersenGens,
        sq: Scalar,
        floor_sqr: Scalar,
        round_square: Scalar,
        blinding_factor_sq: Scalar,
        blinding_factor_floor_sqr: Scalar,
        blinding_factor_round_square: Scalar,
        commitment_floor_sqr: CompressedRistretto,
        transcript: &mut Transcript,
    ) -> Result<Self, ProofError> {
        let square_zk_1 = SquareZKProof::create(
            pedersen_generators,
            floor_sqr,
            blinding_factor_floor_sqr,
            blinding_factor_round_square,
            commitment_floor_sqr,
            transcript,
        )?;

        // Now we need to prove the the value committed in commitment_round_square is smaller than
        // the one committed in commitment_sq
        let subtracted_blinding = &blinding_factor_sq - &blinding_factor_round_square;
        let subtracted = u64::from_le_bytes(
            ((&sq - &round_square).to_bytes()[0..8])
                .try_into()
                .expect("Should never happen as we are taking a slice of 8."),
        );

        let (leq_1, _) = RangeProof::prove_single(
            bulletproof_generators,
            &pedersen_generators,
            transcript,
            subtracted,
            &subtracted_blinding,
            32,
        )?;

        // Now we do the same, but with floor_sq + 1
        let blinding_floor_sqr_p1 = blinding_factor_floor_sqr.clone();
        let commitment_floor_sqr_p1 =
            commitment_floor_sqr.decompress().ok_or_else(|| ProofError::FormatError)?
                + pedersen_generators.B;

        let round_square_p1 = (&floor_sqr + &Scalar::one()) * (&floor_sqr + &Scalar::one());
        let blinding_round_square_p1 = Scalar::random(&mut thread_rng());
        let commitment_round_square_p1 =
            pedersen_generators.commit(round_square_p1, blinding_round_square_p1);
        let square_zk_2 = SquareZKProof::create(
            pedersen_generators,
            &floor_sqr + &Scalar::one(),
            blinding_floor_sqr_p1,
            blinding_round_square_p1,
            commitment_floor_sqr_p1.compress(),
            transcript,
        )?;

        // Now we need to prove the the value committed in commitment_round_square_p1 is greater than
        // the one committed in commitment_sq
        let subtracted_blinding_p1 = &blinding_round_square_p1 - &blinding_factor_sq;
        let subtracted_p1 = u64::from_le_bytes(
            ((&round_square_p1 - &sq).to_bytes()[0..8])
                .try_into()
                .expect("Should never happen as we are taking a slice of 8."),
        );

        let (leq_2, _) = RangeProof::prove_single(
            bulletproof_generators,
            &pedersen_generators,
            transcript,
            subtracted_p1,
            &subtracted_blinding_p1,
            32,
        )?;

        Ok(FloatingSquareZKProof {
            commitment_round_square_p1: commitment_round_square_p1.compress(),
            leq_1,
            leq_2,
            square_zk_1,
            square_zk_2,
        })
    }

    pub fn verify(
        self,
        bulletproofs_generators: &BulletproofGens,
        pedersen_generators: PedersenGens,
        // commitment of the floor of the square root
        commitment_floor_sqr: CompressedRistretto,
        // commitment of the square of the floor of the square root
        commitment_round_sq: CompressedRistretto,
        // commitment of the square in question
        commitment_sq: CompressedRistretto,
        transcript: &mut Transcript,
    ) -> Result<(), ProofError> {
        let subtracted_commitment =
            commitment_sq.decompress().ok_or_else(|| ProofError::FormatError)? -
                commitment_round_sq.decompress().ok_or_else(|| ProofError::FormatError)?;

        let commitment_floor_sqr_p1 =
            commitment_floor_sqr.decompress().ok_or_else(|| ProofError::FormatError)? +
                pedersen_generators.B;
        let subtracted_commitment_p1 =
            self.commitment_round_square_p1.decompress().ok_or_else(|| ProofError::FormatError)? -
                commitment_sq.decompress().ok_or_else(|| ProofError::FormatError)?;

        if

        self.square_zk_1.verify(
            pedersen_generators,
            commitment_round_sq,
            commitment_floor_sqr,
            transcript,
        ).is_ok()

            &&

            self
            .leq_1
            .verify_single(
                &bulletproofs_generators,
                &pedersen_generators,
                transcript,
                &subtracted_commitment.compress(),
                32,
            ).is_ok()

            &&

            self.square_zk_2.verify(
            pedersen_generators,
            self.commitment_round_square_p1,
            commitment_floor_sqr_p1.compress(),
            transcript
            ).is_ok()

            &&

            self.leq_2
            .verify_single(
                &bulletproofs_generators,
                &pedersen_generators,
                transcript,
                &subtracted_commitment_p1.compress(),
                32
            ).is_ok()
        {
            Ok(())
        }
        else
        {
            Err(ProofError::VerificationError)
        }
    }
}

#[derive(Clone)]
struct SquareZKProof {
    equality_proof: EqualityZKProof,
}

impl SquareZKProof {
    fn create(
        pedersen_generators: PedersenGens,
        sqr: Scalar,
        blinding_factor_sqr: Scalar,
        blinding_factor_sq: Scalar,
        commitment_sqr: CompressedRistretto,
        transcript: &mut Transcript,
    ) -> Result<Self, ProofError> {
        // We calculate the blinding factor of the commitment of sqr over commitment base
        // announcement_sqr
        let blinding_commitment_sq: Scalar = &blinding_factor_sq - sqr * blinding_factor_sqr;

        // We generate new pedersen generators
        let new_pedersen_generators = PedersenGens {
            B: commitment_sqr.decompress()
                .ok_or_else(|| ProofError::FormatError)?,
            B_blinding: pedersen_generators.B_blinding,
        };

        // Now we need to prove that `commitment_sqr` and `commitment_sq` share the same discrete
        // log. For that we need to generate PedersenVecGenerators from the PedersenGens
        let vec_pedersen_generators = PedersenVecGens::from(pedersen_generators);
        let vec_new_pedersen_generators = PedersenVecGens::from(new_pedersen_generators);

        let equality_proof = EqualityZKProof::prove_equality(
            &vec_pedersen_generators,
            &vec_new_pedersen_generators,
            &vec![sqr],
            blinding_factor_sqr,
            blinding_commitment_sq,
            transcript,
        )?;

        Ok(SquareZKProof {
            equality_proof: equality_proof,
        })
    }

    fn verify(
        self,
        pedersen_generators: PedersenGens,
        commitment_sq: CompressedRistretto,
        commitment_sqr: CompressedRistretto,
        transcript: &mut Transcript,
    ) -> Result<(), ProofError> {
        // Again, we need to verify with Pedersen generators in the form of a vector, and
        // we need to generate pedersen generators out of the commitment

        let vec_pedersen_generators = PedersenVecGens::from(pedersen_generators);
        let vec_new_pedersen_generators = PedersenVecGens::from(PedersenGens {
            B: commitment_sqr.decompress()
                .ok_or_else(|| ProofError::FormatError)?,
            B_blinding: pedersen_generators.B_blinding,
        });

        self.equality_proof.verify_equality(
            &vec_pedersen_generators,
            &vec_new_pedersen_generators,
            commitment_sqr,
            commitment_sq,
            transcript,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_proof_works() {
        let bulletproof_generators = BulletproofGens::new(32, 1);
        let pedersen_generators = PedersenGens::default();
        let sq = Scalar::from(12323u64);
        let floor_sqr = Scalar::from(111u64);
        let round_sq = Scalar::from(12321u64);
        let mut transcript = Transcript::new(b"testProofFloorSquare");

        let blinding_sq = Scalar::random(&mut thread_rng());
        let commitment_sq = pedersen_generators.commit(sq, blinding_sq);

        let blinding_floor_sqr = Scalar::random(&mut thread_rng());
        let commitment_floor_sqr = pedersen_generators.commit(floor_sqr, blinding_floor_sqr);

        let blinding_round_sq = Scalar::random(&mut thread_rng());
        let commitment_round_sq = pedersen_generators.commit(round_sq, blinding_round_sq);

        let proof = FloatingSquareZKProof::create(
            &bulletproof_generators,
            pedersen_generators,
            sq,
            floor_sqr,
            round_sq,
            blinding_sq,
            blinding_floor_sqr,
            blinding_round_sq,
            commitment_floor_sqr.compress(),
            &mut transcript,
        ).unwrap();

        let mut transcript = Transcript::new(b"testProofFloorSquare");
        assert!(proof.verify(
            &bulletproof_generators,
            pedersen_generators,
            commitment_floor_sqr.compress(),
            commitment_round_sq.compress(),
            commitment_sq.compress(),
            &mut transcript
        ).is_ok())
    }

    #[test]
    fn test_round_proof_fails() {
        let bulletproof_generators = BulletproofGens::new(32, 1);
        let pedersen_generators = PedersenGens::default();
        let sq = Scalar::from(12323u64);
        let floor_sqr = Scalar::from(110u64);
        let round_sq = Scalar::from(12110u64);
        let mut transcript = Transcript::new(b"testProofFloorSquare");

        let blinding_sq = Scalar::random(&mut thread_rng());
        let commitment_sq = pedersen_generators.commit(sq, blinding_sq);

        let blinding_floor_sqr = Scalar::random(&mut thread_rng());
        let commitment_floor_sqr = pedersen_generators.commit(floor_sqr, blinding_floor_sqr);

        let blinding_round_sq = Scalar::random(&mut thread_rng());
        let commitment_round_sq = pedersen_generators.commit(round_sq, blinding_round_sq);

        let proof = FloatingSquareZKProof::create(
            &bulletproof_generators,
            pedersen_generators,
            sq,
            floor_sqr,
            round_sq,
            blinding_sq,
            blinding_floor_sqr,
            blinding_round_sq,
            commitment_floor_sqr.compress(),
            &mut transcript,
        ).unwrap();

        let mut transcript = Transcript::new(b"testProofFloorSquare");
        assert!(proof.verify(
            &bulletproof_generators,
            pedersen_generators,
            commitment_floor_sqr.compress(),
            commitment_round_sq.compress(),
            commitment_sq.compress(),
            &mut transcript
        ).is_err())
    }

    #[test]
    fn test_square_proof_works() {
        let ped_gens = PedersenGens::default();
        let sq = Scalar::from(12321u64);
        let sqr = Scalar::from(111u64);
        let mut transcript = Transcript::new(b"testProofSquare");

        let blinding_sq = Scalar::random(&mut thread_rng());
        let commitment_sq = ped_gens.commit(sq, blinding_sq);

        let blinding_sqr = Scalar::random(&mut thread_rng());
        let commitment_sqr = ped_gens.commit(sqr, blinding_sqr);

        let proof = SquareZKProof::create(
            ped_gens,
            sqr,
            blinding_sqr,
            blinding_sq,
            commitment_sqr.compress(),
            &mut transcript,
        ).unwrap();

        transcript = Transcript::new(b"testProofSquare");
        assert!(proof.verify(
            ped_gens,
            commitment_sq.compress(),
            commitment_sqr.compress(),
            &mut transcript
        ).is_ok())
    }

    #[test]
    fn proof_fails() {
        let ped_gens = PedersenGens::default();
        let sq = Scalar::from(12321u64);
        let sqr = Scalar::from(112u64);
        let mut transcript = Transcript::new(b"testProofSquareFailure");

        let blinding_sq = Scalar::random(&mut thread_rng());
        let commitment_sq = ped_gens.commit(sq, blinding_sq);

        let blinding_sqr = Scalar::random(&mut thread_rng());
        let commitment_sqr = ped_gens.commit(sqr, blinding_sq);

        let proof = SquareZKProof::create(
            ped_gens,
            sqr,
            blinding_sq,
            blinding_sqr,
            commitment_sqr.compress(),
            &mut transcript,
        ).unwrap();

        transcript = Transcript::new(b"testProofSquareFailure");
        assert!(proof.verify(
            ped_gens,
            commitment_sq.compress(),
            commitment_sqr.compress(),
            &mut transcript
        ).is_err())
    }
}
