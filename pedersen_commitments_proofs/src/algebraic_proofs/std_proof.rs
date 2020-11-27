use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use crate::boolean_proofs::square_proof::FloatingSquareZKProof;
use ip_zk_proof::{PedersenGens, BulletproofGens, ProofError};
use rand::thread_rng;
use merlin::Transcript;

#[derive(Clone)]
/// This structure will prove the correct generation of the standard
/// deviation. The tools we may use here are a commitment of the Variance and the Variance.
/// The proof then consists in proving that the square of the committed value we claim to be
/// the std is smaller or equal than the Variance, and that the squre of the committed value plus
/// one is greater than the variance. This suffices to prove that the claimed value is the floor
/// of the std.
pub struct StdProof {
    commitment_sq_std: CompressedRistretto,
    proof_floating_sqr: FloatingSquareZKProof,
}

impl StdProof {
    pub fn create_all(
        bulletproof_generators: &BulletproofGens,
        pedersen_generators: &PedersenGens,
        stds: &Vec<Vec<Scalar>>,
        variances: &Vec<Vec<Scalar>>,
        commitment_std: &Vec<Vec<CompressedRistretto>>,
        blinding_commitment_std: &Vec<Vec<Scalar>>,
        blinding_commitment_variance: &Vec<Vec<Scalar>>
    ) -> Result<Vec<Vec<StdProof>>, ProofError> {
        let mut proofs: Vec<Vec<StdProof>> = stds.iter().map(|_| Vec::new()).collect();
        for (index, a) in stds.into_iter().enumerate() {
            for (jindex, &std) in a.into_iter().enumerate() {
                proofs[index].push(StdProof::create(
                    &bulletproof_generators,
                    pedersen_generators,
                    std,
                    variances[index][jindex],
                    commitment_std[index][jindex],
                    blinding_commitment_std[index][jindex],
                    blinding_commitment_variance[index][jindex]
                )?)
            }
        }
        Ok(proofs)
    }
    pub fn create(
        bulletproof_generators: &BulletproofGens,
        pedersen_generators: &PedersenGens,
        std: Scalar,
        variance: Scalar,
        commitment_std: CompressedRistretto,
        blinding_commitment_std: Scalar,
        blinding_commitment_variance: Scalar,
    ) -> Result<StdProof, ProofError> {
        // This most likely won't exactly equal the variance, as we are working with integer
        // values.
        let squared_std = &std * &std;
        let blinding_factor_round_square = Scalar::random(&mut thread_rng());
        let commitment_sq_std = pedersen_generators.commit(squared_std, blinding_factor_round_square);

        let mut transcript = Transcript::new(b"StandardDeviationProof");

        let square_root_proof = FloatingSquareZKProof::create(
            bulletproof_generators,
            *pedersen_generators,
            variance,
            std,
            squared_std,
            blinding_commitment_variance,
            blinding_commitment_std,
            blinding_factor_round_square,
            commitment_std,
            &mut transcript
        )?;

        Ok(StdProof{
            commitment_sq_std: commitment_sq_std.compress(),
            proof_floating_sqr: square_root_proof
        })
    }

    pub fn verify_all(
        bulletproof_generators: &BulletproofGens,
        pedersen_generators: &PedersenGens,
        commitment_std: &Vec<Vec<CompressedRistretto>>,
        commitment_variance: &Vec<Vec<CompressedRistretto>>,
        proofs: &Vec<Vec<StdProof>>
    ) -> Result<(), ProofError> {
        for (index, a) in proofs.into_iter().enumerate() {
            for (jindex, proof) in a.into_iter().enumerate() {
                proof.clone().verify(
                    &bulletproof_generators,
                    pedersen_generators,
                    commitment_std[index][jindex],
                    commitment_variance[index][jindex]
                )?;
            }
        }
        return Ok(())
    }

    pub fn verify(
        self,
        bulletproof_generators: &BulletproofGens,
        pedersen_generators: &PedersenGens,
        commitment_std: CompressedRistretto,
        commitment_variance: CompressedRistretto,
    ) -> Result<(), ProofError> {
        let mut transcript = Transcript::new(b"StandardDeviationProof");

        self.proof_floating_sqr.verify(
            &bulletproof_generators,
            *pedersen_generators,
            commitment_std,
            self.commitment_sq_std,
            commitment_variance,
            &mut transcript
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebraic_proofs::average_proof::AvgProof;
    use crate::algebraic_proofs::variance_proof::VarianceProof;
    use crate::utils::misc::compute_subtraction_vector;

    #[test]
    fn test_vector_addition() {
        let dummy_sensor_values: Vec<[Vec<Scalar>; 3]> = vec![
            [vec![Scalar::from(12u32), Scalar::from(4u32)], vec![Scalar::from(34u32), Scalar::from(4u32)], vec![Scalar::from(122u32), Scalar::from(4u32)]],
            [vec![Scalar::from(4u32), Scalar::from(42345u32)], vec![Scalar::from(234u32), Scalar::from(4u32)], vec![Scalar::from(134u32), Scalar::from(4u32)]],
            [vec![Scalar::from(134u32), Scalar::from(4u32)], vec![Scalar::from(234u32), Scalar::from(4u32)], vec![Scalar::from(1223u32), Scalar::from(4u32)]]
        ];

        let size_sensors: Vec<usize> = dummy_sensor_values.iter().map(|a| a[0].len()).collect();

        let computed_addition: Vec<Vec<Scalar>> =
            AvgProof::compute_sensors_addition(&dummy_sensor_values);

        // Now we calculate the values of which we will compute the inner product of
        let subtraction_values: Vec<Vec<Vec<Scalar>>> = compute_subtraction_vector(
            &size_sensors,
            &dummy_sensor_values,
            &computed_addition
        );

        let all_variances: Vec<Vec<Scalar>> = VarianceProof::compute_all_variances(&subtraction_values);

        // We compute the variances in python. Attention with rounding errors
        let expected_variances: Vec<Vec<Scalar>> = vec![
            vec![Scalar::from(128u64), Scalar::from(1800u64), Scalar::from(27848u64)],
            vec![Scalar::from(3585520562u64), Scalar::from(105800u64), Scalar::from(33800u64)],
            vec![Scalar::from(33800u64), Scalar::from(105800u64), Scalar::from(2971922u64)]
        ];

        assert_eq!(expected_variances, all_variances);
    }
}