#![allow(non_snake_case)]
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{VartimeMultiscalarMul, IsIdentity};

use core::iter;
use merlin::Transcript;

use rand_core::OsRng;

use crate::generators::PedersenVecGens;
use crate::transcript::TranscriptProtocol;
use ip_zk_proof::ProofError;

#[derive(Clone)]
pub struct EqualityZKProof {
    /// Announcement
    A: CompressedRistretto,
    B: CompressedRistretto,
    /// Response
    r_randomization_1: Scalar,
    r_randomization_2: Scalar,
    r_opening: Vec<Scalar>,
}

impl EqualityZKProof {
    pub fn prove_equality(
        pc_gens_1: &PedersenVecGens,
        pc_gens_2: &PedersenVecGens,
        opening: &Vec<Scalar>,
        randomization_1: Scalar,
        randomization_2: Scalar,
        transcript: &mut Transcript,
    ) -> Result<EqualityZKProof, ProofError> {
        if pc_gens_1.size != opening.len() || pc_gens_2.size != opening.len() {
            return Err(ProofError::InvalidGeneratorsLength);
        }

        let size = opening.len();
        let mut csprng: OsRng = OsRng;

        let randomization_blinding_1 = Scalar::random(&mut csprng);
        let randomization_blinding_2 = Scalar::random(&mut csprng);
        let opening_blinding: Vec<Scalar> =
            (0..size).map(|_| Scalar::random(&mut csprng)).collect();

        let A = pc_gens_1
            .commit(&opening_blinding, randomization_blinding_1)
            .compress();
        let B = pc_gens_2
            .commit(&opening_blinding, randomization_blinding_2)
            .compress();

        transcript.append_point(b"announcement A", &A);
        transcript.append_point(b"announcement B", &B);

        let challenge = transcript.challenge_scalar(b"challenge");

        let r_randomization_1: Scalar = challenge * randomization_1 + randomization_blinding_1;
        let r_randomization_2: Scalar = challenge * randomization_2 + randomization_blinding_2;
        let r_opening = opening_blinding
            .iter()
            .zip(opening.iter())
            .map(|(x, y)| x + challenge * y)
            .collect();

        Ok(EqualityZKProof {
            A,
            B,
            r_randomization_1,
            r_randomization_2,
            r_opening,
        })
    }

    pub fn verify_equality(
        &self,
        pc_gens_1: &PedersenVecGens,
        pc_gens_2: &PedersenVecGens,
        commitment_1: CompressedRistretto,
        commitment_2: CompressedRistretto,
        transcript: &mut Transcript,
    ) -> Result<(), ProofError> {
        transcript.append_point(b"announcement A", &self.A);
        transcript.append_point(b"announcement B", &self.B);

        let challenge = transcript.challenge_scalar(b"challenge");

        let mega_check = RistrettoPoint::optional_multiscalar_mul(
            iter::repeat(Scalar::one()).take(2)
                .chain(iter::repeat(challenge).take(2))
                .chain(iter::once(-self.r_randomization_1))
                .chain(iter::once(-self.r_randomization_2))
                .chain(self.r_opening.clone().into_iter().map(|r| -r))
                .chain(self.r_opening.clone().into_iter().map(|r| -r))
            ,
            iter::once(self.A.decompress())
                .chain(iter::once(self.B.decompress()))
                .chain(iter::once(commitment_1.decompress()))
                .chain(iter::once(commitment_2.decompress()))
                .chain(iter::once(Some(pc_gens_1.B_blinding)))
                .chain(iter::once(Some(pc_gens_2.B_blinding)))
                .chain(pc_gens_1.B.clone().into_iter().map(|B| Some(B)))
                .chain(pc_gens_2.B.clone().into_iter().map(|B| Some(B)))
        )
            .ok_or_else(|| ProofError::VerificationError)?;

        if mega_check.is_identity() {
            Ok(())
        }
        else {
            Err(ProofError::VerificationError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_works() {
        let size = 70;
        let ped_gens_1 = PedersenVecGens::new(size);
        let ped_gens_2 = PedersenVecGens::new_random(size);
        let mut transcript = Transcript::new(b"test");
        let mut csprng: OsRng = OsRng;

        let randomization_1 = Scalar::random(&mut csprng);
        let randomization_2 = Scalar::random(&mut csprng);
        let opening: Vec<Scalar> = (0..size).map(|_| Scalar::random(&mut csprng)).collect();

        let commitment_1 = ped_gens_1.commit(&opening, randomization_1);
        let commitment_2 = ped_gens_2.commit(&opening, randomization_2);

        let proof = EqualityZKProof::prove_equality(
            &ped_gens_1,
            &ped_gens_2,
            &opening,
            randomization_1,
            randomization_2,
            &mut transcript,
        )
        .unwrap();

        transcript = Transcript::new(b"test");
        assert!(proof.verify_equality(
            &ped_gens_1,
            &ped_gens_2,
            commitment_1.compress(),
            commitment_2.compress(),
            &mut transcript
        ).is_ok())
    }

    #[test]
    fn proof_fails() {
        let size = 70;
        let ped_gens_1 = PedersenVecGens::new(size);
        let ped_gens_2 = PedersenVecGens::new_random(size);
        let mut transcript = Transcript::new(b"test");
        let mut csprng: OsRng = OsRng;

        let randomization_1 = Scalar::random(&mut csprng);
        let randomization_2 = Scalar::random(&mut csprng);
        let opening: Vec<Scalar> = (0..size).map(|_| Scalar::random(&mut csprng)).collect();
        let fake_opening: Vec<Scalar> = (0..size).map(|_| Scalar::random(&mut csprng)).collect();

        let commitment_1 = ped_gens_1.commit(&opening, randomization_1);
        let commitment_2 = ped_gens_2.commit(&fake_opening, randomization_2);

        let proof = EqualityZKProof::prove_equality(
            &ped_gens_1,
            &ped_gens_2,
            &opening,
            randomization_1,
            randomization_2,
            &mut transcript,
        )
        .unwrap();

        transcript = Transcript::new(b"test");
        assert!(proof.verify_equality(
            &ped_gens_1,
            &ped_gens_2,
            commitment_1.compress(),
            commitment_2.compress(),
            &mut transcript
        ).is_err())
    }

    #[test]
    fn test_single_value_proof() {
        let size = 1;
        let ped_gens_1 = PedersenVecGens::new(size);
        let ped_gens_2 = PedersenVecGens::new_random(size);
        let mut transcript = Transcript::new(b"test");
        let mut csprng: OsRng = OsRng;

        let randomization_1 = Scalar::random(&mut csprng);
        let randomization_2 = Scalar::random(&mut csprng);
        let opening: Vec<Scalar> = (0..size).map(|_| Scalar::random(&mut csprng)).collect();

        let commitment_1 = ped_gens_1.commit(&opening, randomization_1);
        let commitment_2 = ped_gens_2.commit(&opening, randomization_2);

        let proof = EqualityZKProof::prove_equality(
            &ped_gens_1,
            &ped_gens_2,
            &opening,
            randomization_1,
            randomization_2,
            &mut transcript,
        )
        .unwrap();

        transcript = Transcript::new(b"test");
        assert!(proof.verify_equality(
            &ped_gens_1,
            &ped_gens_2,
            commitment_1.compress(),
            commitment_2.compress(),
            &mut transcript
        ).is_ok())
    }
}
