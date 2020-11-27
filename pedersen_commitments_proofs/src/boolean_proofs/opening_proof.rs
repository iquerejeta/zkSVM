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

#[derive(Clone, Debug)]
pub struct OpeningZKProof {
    /// Announcement
    A: CompressedRistretto,
    /// Response
    r_randomization: Scalar,
    r_opening: Vec<Scalar>,
}

impl OpeningZKProof {
    pub fn prove_opening(
        pc_gens: &PedersenVecGens,
        opening: &Vec<Scalar>,
        randomization: Scalar,
        transcript: &mut Transcript,
    ) -> OpeningZKProof {
        let size = opening.len();
        let mut csprng: OsRng = OsRng;

        let randomization_blinding = Scalar::random(&mut csprng);
        let opening_blinding: Vec<Scalar> =
            (0..size).map(|_| Scalar::random(&mut csprng)).collect();

        let announcement = pc_gens
            .commit(&opening_blinding, randomization_blinding)
            .compress();
        transcript.append_point(b"announcement", &announcement);

        let challenge = transcript.challenge_scalar(b"challenge");

        let r_randomization: Scalar = challenge * randomization + randomization_blinding;
        let r_opening = opening_blinding
            .iter()
            .zip(opening.iter())
            .map(|(x, y)| x + challenge * y)
            .collect();

        OpeningZKProof {
            A: announcement,
            r_randomization,
            r_opening,
        }
    }

    pub fn verify_opening_knowledge(
        self,
        pc_gens: &PedersenVecGens,
        commitment: CompressedRistretto,
        transcript: &mut Transcript,
    ) -> Result<(), ProofError> {
        transcript.append_point(b"announcement", &self.A);
        let challenge = transcript.challenge_scalar(b"challenge");

        let mega_check = RistrettoPoint::optional_multiscalar_mul(
            iter::once(Scalar::one())
                .chain(iter::once(challenge))
                .chain(iter::once(- &self.r_randomization))
                .chain(self.r_opening.into_iter().map(|r| -r))
            ,
            iter::once(self.A.decompress())
                .chain(iter::once(commitment.decompress()))
                .chain(iter::once(Some(pc_gens.B_blinding)))
                .chain(pc_gens.B.clone().into_iter().map(|B| Some(B)))
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
        let ped_gens = PedersenVecGens::new(size);
        let mut transcript = Transcript::new(b"test");
        let mut csprng: OsRng = OsRng;

        let randomization = Scalar::random(&mut csprng);
        let opening: Vec<Scalar> = (0..size).map(|_| Scalar::random(&mut csprng)).collect();

        let commitment = ped_gens.commit(&opening, randomization).compress();

        let proof =
            OpeningZKProof::prove_opening(&ped_gens, &opening, randomization, &mut transcript);

        transcript = Transcript::new(b"test");
        assert!(proof.verify_opening_knowledge(&ped_gens, commitment, &mut transcript).is_ok())
    }

    #[test]
    fn proof_fails() {
        let size = 70;
        let ped_gens = PedersenVecGens::new(size);
        let mut transcript = Transcript::new(b"test");
        let mut csprng: OsRng = OsRng;

        let randomization = Scalar::random(&mut csprng);
        let opening: Vec<Scalar> = (0..size).map(|_| Scalar::random(&mut csprng)).collect();
        let fake_opening: Vec<Scalar> = (0..size).map(|_| Scalar::random(&mut csprng)).collect();

        let commitment = ped_gens.commit(&fake_opening, randomization).compress();

        let proof =
            OpeningZKProof::prove_opening(&ped_gens, &opening, randomization, &mut transcript);

        transcript = Transcript::new(b"test");
        assert!(proof.verify_opening_knowledge(&ped_gens, commitment, &mut transcript).is_err())
    }
}
