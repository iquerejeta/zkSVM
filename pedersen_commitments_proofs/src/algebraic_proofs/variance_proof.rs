use ip_zk_proof::{InnerProductZKProof, BulletproofGens, PedersenGens, inner_product, ProofError};

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};

use merlin::Transcript;

use rand::thread_rng;
use crate::PedersenVecGens;
use crate::boolean_proofs::equality_proof::EqualityZKProof;
use crate::algebraic_proofs::diff_vector_gen_proof::{prove_equality_commitments, verify_proof_equality_commitments};
use crate::algebraic_proofs::std_proof::StdProof;
use crate::utils::commitment_fns::multiple_commit;
use crate::utils::misc::compute_subtraction_vector;

define_proof! {
    dlog,
    "DLog",
    (x),
    (A),
    (G) :
    A = (x * G)
}

#[derive(Clone)]
pub struct VarianceProof {
    comm_sensors_base_H: Vec<Vec<CompressedRistretto>>,
    proofs_base_H_comms: Vec<Vec<EqualityZKProof>>,
    variance_commitment: Vec<Vec<CompressedRistretto>>,
    proofs_variance: Vec<Vec<InnerProductZKProof>>,
    std_commitment: Vec<Vec<CompressedRistretto>>,
    proofs_std: Vec<Vec<StdProof>>
}

impl VarianceProof {
    pub fn create(
        all_sensor_vectors: &Vec<[Vec<Scalar>; 3]>,
        all_sensor_stds: &Vec<Vec<Scalar>>,
        sensor_additions: &Vec<Vec<Scalar>>,
        variances: &Vec<Vec<Scalar>>,
        bulletproof_generators: &BulletproofGens,
        pedersen_generators: &PedersenGens,
        pedersen_vec_generators: &PedersenVecGens,
        // base of the "right hand side" bulleproof generators
        secondary_pedersen_vec_generators: &PedersenVecGens,
        // Blinding factors of the signed commitments of the sensors
        signed_commitment_blinding_factors: &Vec<Vec<Scalar>>,
        // Blinding factors of the diff commitments of the sensors
        diff_blinding_factors: &Vec<Vec<Scalar>>,
        size_sensors: &Vec<usize>,
        size_vectors: usize,
    ) -> Result<Self, ProofError> {
        let length_all_vectors = all_sensor_vectors.len();
        let initial_nr_sensors = signed_commitment_blinding_factors.len();
        // We need to prove the commitment of the vectors with the sensor data with base H
        let (comm_sensors_base_H, blinding_sensors_base_H) = multiple_commit(
            secondary_pedersen_vec_generators,
            &all_sensor_vectors
        );

        let proofs_base_H_comms: Vec<Vec<EqualityZKProof>> = prove_equality_commitments(
            &pedersen_vec_generators,
            &vec![secondary_pedersen_vec_generators.clone(); length_all_vectors],
            &all_sensor_vectors,
            &signed_commitment_blinding_factors,
            &blinding_sensors_base_H
        );

        // Now we calculate the values of which we will compute the inner product of
        let subtraction_values: Vec<Vec<Vec<Scalar>>> = compute_subtraction_vector(
            &size_sensors,
            &all_sensor_vectors,
            &sensor_additions
        );

        let blinders_comm_variances: Vec<Vec<Scalar>> = (0..length_all_vectors).map(
            |_| (0..3).map(
                |_| Scalar::random(&mut thread_rng())
            ).collect()
        ).collect();

        let mut variances_a_blindings = vec![Vec::new(); length_all_vectors];
        for (i, a) in signed_commitment_blinding_factors.iter().enumerate() {
            for (j, signed_hash_blinding) in a.iter().enumerate() {
                variances_a_blindings[i].push(
                    Scalar::from(size_sensors[i] as u64) * signed_hash_blinding - &sensor_additions[i][j] +
                        Scalar::from(size_sensors[i] as u64) * blinding_sensors_base_H[i][j] - &sensor_additions[i][j]
                )
            }
        }

        for (i, a) in diff_blinding_factors.iter().enumerate() {
            for (j, sensor_diff_blinding) in a.iter().enumerate() {
                variances_a_blindings[initial_nr_sensors + i].push(
                    Scalar::from(size_sensors[initial_nr_sensors + i] as u64) * sensor_diff_blinding - &sensor_additions[initial_nr_sensors + i][j] +
                        Scalar::from(size_sensors[initial_nr_sensors + i] as u64) * blinding_sensors_base_H[initial_nr_sensors + i][j] - &sensor_additions[initial_nr_sensors + i][j]
                )
            }
        }

        let proofs_variances = VarianceProof::all_proofs_variance(
            &subtraction_values,
            &bulletproof_generators,
            &pedersen_generators,
            &blinders_comm_variances,
            &variances_a_blindings,
            size_vectors
        );

        let stds_blindings: Vec<Vec<Scalar>> = (0..length_all_vectors).map(
            |_| (0..3).map(
                |_| Scalar::random(&mut thread_rng())
            ).collect()
        ).collect();

        let stds_commitments = all_sensor_stds.into_iter()
            .zip(stds_blindings.clone().into_iter())
            .map(|(stds, blindings)|
                stds.into_iter()
                    .zip(blindings.into_iter())
                    .map(|(&std, blinding)| pedersen_generators.commit(std, blinding).compress())
                    .collect())
            .collect();

        let proof_std = StdProof::create_all(
            &bulletproof_generators,
            pedersen_generators,
            &all_sensor_stds,
            &variances,
            &stds_commitments,
            &stds_blindings,
            &blinders_comm_variances
        )?;

        Ok(VarianceProof{
            comm_sensors_base_H,
            proofs_base_H_comms,
            variance_commitment: proofs_variances.1,
            proofs_variance: proofs_variances.0,
            std_commitment: stds_commitments,
            proofs_std: proof_std,
        })
    }

    pub fn verify(
        self,
        signed_commitments: &Vec<Vec<CompressedRistretto>>,
        diff_commitments: &Vec<Vec<CompressedRistretto>>,
        last_exps: &Vec<Vec<RistrettoPoint>>,
        average_commitment_base_G: &Vec<Vec<RistrettoPoint>>,
        average_commitment_base_H: &Vec<Vec<RistrettoPoint>>,
        bulletproof_generators: &BulletproofGens,
        pedersen_generators: &PedersenGens,
        pedersen_vec_generators: &PedersenVecGens,
        // base of the "right hand side" bulleproof generators
        secondary_pedersen_vec_generators: &PedersenVecGens,
        size_sensors: &Vec<usize>,
        size: usize,
        length_all_vectors: usize
    ) -> Result<(), ProofError> {
        let initial_nr_sensors = signed_commitments.len();

        // So
        // A =
        //     size_vec_acc * all_signed_hash.0[0][0] - avg_comm_base_G  +
        //     size_vec_acc * acc_com_base_H - avg_comm_base_H
        //
        // And so the a_blinding factor needs to be
        // some_blinding_factor =
        //        size_vec_acc * blinder_used_signed_hash - average +
        //        size_vec_acc * blinder_used_hash_baseH - average

        let mut expected_As: Vec<Vec<RistrettoPoint>> = vec![Vec::new(); length_all_vectors];
        for (i, a) in signed_commitments.iter().enumerate() {
            for (j, signed_hash) in a.iter().enumerate() {
                expected_As[i].push(
                    Scalar::from(size_sensors[i] as u64) * signed_hash.decompress().unwrap() - average_commitment_base_G[i][j] +
                        Scalar::from(size_sensors[i] as u64) * self.comm_sensors_base_H[i][j].decompress().unwrap() - average_commitment_base_H[i][j]
                )
            }
        }

        for (i, a) in diff_commitments.iter().enumerate() {
            for (j, hash_diff) in a.iter().enumerate() {
                expected_As[initial_nr_sensors + i].push(
                    Scalar::from(size_sensors[initial_nr_sensors + i] as u64) * (hash_diff.decompress().unwrap() - last_exps[i][j]) - average_commitment_base_G[initial_nr_sensors + i][j] +
                        Scalar::from(size_sensors[initial_nr_sensors + i] as u64) * self.comm_sensors_base_H[initial_nr_sensors + i][j].decompress().unwrap() - average_commitment_base_H[initial_nr_sensors + i][j]
                )
            }
        }

        verify_proof_equality_commitments(
            &pedersen_vec_generators,
            &vec![secondary_pedersen_vec_generators.clone(); length_all_vectors],
            &signed_commitments,
            &self.comm_sensors_base_H,
            &self.proofs_base_H_comms
        )?;

        VarianceProof::all_proof_variance_verify(
                &bulletproof_generators,
                &pedersen_generators,
                &self.variance_commitment,
                &self.proofs_variance,
                size,
                &expected_As
        )?;

        StdProof::verify_all(
                &bulletproof_generators,
                pedersen_generators,
                &self.std_commitment,
                &self.variance_commitment,
                &self.proofs_std
        )?;

        Ok(())
    }

    pub fn compute_all_variances(
        subtracted_values: &Vec<Vec<Vec<Scalar>>>,
    ) -> Vec<Vec<Scalar>> {
        subtracted_values.iter().map(
            |i| i.iter().map(
                |subtracted_vector| inner_product(&subtracted_vector, &subtracted_vector)
            ).collect()
        ).collect()
    }

    fn all_proofs_variance(
        subtracted_averages: &Vec<Vec<Vec<Scalar>>>,
        bp_gens: &BulletproofGens,
        pd_gens: &PedersenGens,
        v_blindings: &Vec<Vec<Scalar>>,
        a_blindings: &Vec<Vec<Scalar>>,
        size: usize
    ) -> (Vec<Vec<InnerProductZKProof>>, Vec<Vec<CompressedRistretto>>) {
        let mut compressed_points = vec![Vec::new(); subtracted_averages.len()];
        let mut ip_proofs = vec![Vec::new(); subtracted_averages.len()];
        for (i, a) in subtracted_averages.iter().enumerate() {
            for (j, b) in a.iter().enumerate() {
                let proof = VarianceProof::proof_variance(
                    b,
                    &bp_gens,
                    &pd_gens,
                    v_blindings[i][j],
                    a_blindings[i][j],
                    size
                );
                ip_proofs[i].push(proof.0);
                compressed_points[i].push(proof.1);
            }
        }
        (ip_proofs, compressed_points)
    }

    fn all_proof_variance_verify(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        commitments: &Vec<Vec<CompressedRistretto>>,
        proofs: &Vec<Vec<InnerProductZKProof>>,
        size_vector: usize,
        expected_As: &Vec<Vec<RistrettoPoint>>
    ) -> Result<(), ProofError> {
        for (i, a) in proofs.iter().enumerate() {
            for (j, b) in a.iter().enumerate() {
                VarianceProof::verify_variance(
                    &bp_gens,
                    pc_gens,
                    commitments[i][j],
                    b,
                    size_vector,
                    expected_As[i][j]
                )?;
            }
        }
        Ok(())
    }

    fn proof_variance(subtracted_average: &Vec<Scalar>,
                      bp_gens: &BulletproofGens,
                      pd_gens: &PedersenGens,
                      v_blinding: Scalar,
                      a_blinding: Scalar,
                      size: usize)
                      -> (InnerProductZKProof, CompressedRistretto)
    {
        let variance = inner_product(&subtracted_average.clone(), &subtracted_average.clone()); // without division

        let mut transcript = Transcript::new(b"InnerProductAverage");
        let proof = InnerProductZKProof::prove_single(
            bp_gens,
            pd_gens,
            &mut transcript,
            variance,
            &subtracted_average,
            &subtracted_average,
            v_blinding,
            a_blinding,
            size,
            &mut thread_rng()
        ).unwrap();

        proof
    }

    fn verify_variance(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        commitment_variance: CompressedRistretto,
        ip_proof: &InnerProductZKProof,
        size_vector: usize,
        expected_A: RistrettoPoint
    )
        -> Result<(), ProofError>
    {
        // We need to verify that S of the proof is indeed as we expect it to be
        assert!(ip_proof.verify_expected_A(expected_A.compress()));
        let mut transcript = Transcript::new(b"InnerProductAverage");
        ip_proof.verify_single(
            &bp_gens, &pc_gens, &mut transcript, &commitment_variance, size_vector, &mut thread_rng()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebraic_proofs::average_proof::AvgProof;

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