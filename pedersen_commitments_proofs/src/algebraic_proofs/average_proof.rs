use ip_zk_proof::{InnerProductZKProof, BulletproofGens, PedersenGens, inner_product, ProofError};

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};

use core::iter;
use merlin::Transcript;
use zkp::CompactProof;

// ZKPs macros
define_proof! {
          avg_comm_proof,   // Name of the module for generated implementation
          "AvgComm",       // Label for the proof statement
          (x, r),         // Secret variables
          (A, G, B, H),   // Public variables unique to each proof
          (C) :        // Public variables common between proofs
          A = (x * G + r * B), // Statements to prove
          C = (x * H)
}

define_proof! {
    dlog,
    "DLog",
    (x),
    (A),
    (G) :
    A = (x * G)
}

#[derive(Clone)]
/// We describe the AvgProof structure, which encapsulates all the proves necessary around the
/// average. In our paper we calculate the Sum and not the Average. Here we do the same, but we
/// refer to it as Avg proof, as we compute a factor of the average, and it makes readability easier
pub struct AvgProof {
    // Average commitment (with ped_generators)
    pub average_commitment: Vec<Vec<CompressedRistretto>>,
    // Proof Average computation
    proof_average: Vec<Vec<InnerProductZKProof>>,
    // The commitment of the average vector with base G and H of bp_generators
    pub average_commitment_base_G: Vec<Vec<RistrettoPoint>>,
    pub average_commitment_base_H: Vec<Vec<RistrettoPoint>>,
    // Proofs of correctness
    proofs_avg_comm_base_G: Vec<Vec<CompactProof>>,
    proofs_avg_comm_base_H: Vec<Vec<CompactProof>>,
}

impl AvgProof{
    pub fn create(
        size_sensors: &Vec<usize>,
        bp_generators: &BulletproofGens,
        ped_generators: &PedersenGens,
        input_vectors: &Vec<[Vec<Scalar>; 3]>,
        v_blindings: &Vec<Vec<Scalar>>,
        a_blindings: &Vec<Vec<Scalar>>,
    ) -> AvgProof {
        let sensor_additions = AvgProof::compute_sensors_addition(
            &input_vectors
        );

        let mut multiply_ped_sign_acc_bases_G: Vec<RistrettoPoint> = Vec::new();
        for &size in size_sensors {
            let mut value = ped_generators.B_blinding;
            for base in bp_generators.G_vec[0].clone()[0..size].to_vec() {
                value += &base;
            }
            multiply_ped_sign_acc_bases_G.push(value);
        }

        let mut multiply_ped_acc_bases_H: Vec<RistrettoPoint> = Vec::new();
        for &size in size_sensors {
            let mut value = ped_generators.B_blinding;
            for base in bp_generators.H_vec[0].clone()[0..size].to_vec() {
                value += &base;
            }
            multiply_ped_acc_bases_H.push(value);
        }

        let length_vectors = input_vectors.len();
        let mut compressed_points: Vec<Vec<CompressedRistretto>> =
            (0..length_vectors).map(
                |_| Vec::new()
            ).collect();
        let mut ip_proofs: Vec<Vec<InnerProductZKProof>> =
            (0..length_vectors).map(
                |_| Vec::new()
            ).collect();
        for (i, a) in input_vectors.iter().enumerate() {
            for (j, b) in a.iter().enumerate() {
                let proof = AvgProof::single_proof_average(
                    &bp_generators,
                    &ped_generators,
                    b,
                    v_blindings[i][j],
                    a_blindings[i][j],
                );
                compressed_points[i].push(proof.0);
                ip_proofs[i].push(proof.1)
            }
        }
        // Generate the average commitment with the two bases. Here we use the multiplied bases
        // of each vector commitment given that the value to commit is one repeated number (the sum)
        let average_commitment_base_G: Vec<Vec<RistrettoPoint>> = sensor_additions
            .clone()
            .into_iter()
            .enumerate()
            .map(
            |(index, a)| a.iter().map(
                |sensor_addition| sensor_addition * multiply_ped_sign_acc_bases_G[index]
            ).collect()
        ).collect();

        let average_commitment_base_H: Vec<Vec<RistrettoPoint>> = sensor_additions
            .clone()
            .into_iter()
            .enumerate()
            .map(
            |(index, a)| a.iter().map(
                |sensor_addition| sensor_addition * multiply_ped_acc_bases_H[index]
            ).collect()
        ).collect();

        let proofs_avg_comm_base_G = AvgProof::all_proof_avg_comm(
            &ped_generators,
            &sensor_additions,
            &v_blindings,
            &compressed_points,
            &average_commitment_base_G,
            &multiply_ped_sign_acc_bases_G
        );

        let proofs_avg_comm_base_H = AvgProof::all_proof_avg_comm(
            &ped_generators,
            &sensor_additions,
            &v_blindings,
            &compressed_points,
            &average_commitment_base_H,
            &multiply_ped_acc_bases_H
        );
        AvgProof{
            average_commitment: compressed_points,
            proof_average: ip_proofs,
            average_commitment_base_G,
            average_commitment_base_H,
            proofs_avg_comm_base_G,
            proofs_avg_comm_base_H,
        }
    }

    fn single_proof_average(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        input_vector: &Vec<Scalar>,
        v_blinding: Scalar,
        a_blinding: Scalar,
    ) -> (CompressedRistretto, InnerProductZKProof)
    {
        let mut rng = rand::thread_rng();
        let size = input_vector.len();
        let one_vector: Vec<Scalar> = iter::repeat(Scalar::one()).take(size).collect();

        let sum = inner_product(&input_vector, &one_vector);

        let mut transcript = Transcript::new(b"InnerProductAverage");
        let (proof, commitment_sum) = InnerProductZKProof::prove_single(
            bp_gens,
            pc_gens,
            &mut transcript,
            sum,
            input_vector,
            &one_vector,
            v_blinding,
            a_blinding,
            size,
            &mut rng,
        ).unwrap();

        (commitment_sum, proof)
    }
    /// Generate a proof that the committed value is indeed the average
    fn all_proof_avg_comm (
        pd_generators: &PedersenGens,
        sensor_additions: &[Vec<Scalar>],
        add_comm_blindings: &Vec<Vec<Scalar>>,
        avg_comm: &Vec<Vec<CompressedRistretto>>,
        avg_comm_base: &Vec<Vec<RistrettoPoint>>,
        multiplied_ped_sign_bases: &Vec<RistrettoPoint>
    ) -> Vec<Vec<CompactProof>>{
        // Now we prove correcness, both for base G and base H

        let mut transcript = Transcript::new(b"ProofAverageCommitmentG");
        (0..4).map(
            |i| (0..3).map(
                |j| avg_comm_proof::prove_compact(
                    &mut transcript,
                    avg_comm_proof::ProveAssignments {
                        x: &sensor_additions[i][j],
                        r: &add_comm_blindings[i][j],
                        A: &avg_comm[i][j].decompress().unwrap(),
                        G: &pd_generators.B,
                        B: &pd_generators.B_blinding,
                        C: &avg_comm_base[i][j],
                        H: &multiplied_ped_sign_bases[i],
                    },
                ).0
            ).collect()
        ).collect()
    }

    pub fn compute_sensors_addition(
        sensors_vectors: &Vec<[Vec<Scalar>; 3]>
    ) -> Vec<Vec<Scalar>> {
        let mut additions: Vec<Vec<Scalar>> = (0..sensors_vectors.len()).map(
            |_| Vec::new()
        ).collect();
        for (index, sensor_vector) in sensors_vectors.iter().enumerate() {
            additions[index] =
                sensor_vector
                    .iter()
                    .map(|x| x.iter().sum())
                    .collect();
        }
        additions
    }

    /// Verify all proofs contained in AvgProof. This is, the proof of correctness of
    /// the average, and the proofs of commitment under other bases.
    pub fn verify(
        &self,
        bp_generators: &BulletproofGens,
        ped_generators: &PedersenGens,
        size_vector: usize,
        size_sensors: &Vec<usize>
    ) -> Result<(), ProofError> {
        let mut multiply_ped_sign_acc_bases_G: Vec<RistrettoPoint> = Vec::new();
        for &size in size_sensors {
            let mut value = ped_generators.B_blinding;
            for base in bp_generators.G_vec[0].clone()[0..size].to_vec() {
                value += &base;
            }
            multiply_ped_sign_acc_bases_G.push(value);
        }

        let mut multiply_ped_acc_bases_H: Vec<RistrettoPoint> = Vec::new();
        for &size in size_sensors {
            let mut value = ped_generators.B_blinding;
            for base in bp_generators.H_vec[0].clone()[0..size].to_vec() {
                value += &base;
            }
            multiply_ped_acc_bases_H.push(value);
        }

        AvgProof::verify_avg_comm_different_base(
            &self.proofs_avg_comm_base_G,
            ped_generators,
            &self.average_commitment,
            &self.average_commitment_base_G,
            &multiply_ped_sign_acc_bases_G
        )?;

        AvgProof::verify_avg_comm_different_base(
            &self.proofs_avg_comm_base_H,
            ped_generators,
            &self.average_commitment,
            &self.average_commitment_base_H,
            &multiply_ped_acc_bases_H
        )?;

        AvgProof::verify_avg(
            bp_generators,
            ped_generators,
            &self.proof_average,
            &self.average_commitment,
            size_vector
        )?;

        Ok(())
    }

    fn verify_avg_comm_different_base(
        proofs: &Vec<Vec<CompactProof>>,
        pd_generators: &PedersenGens,
        avg_comm: &Vec<Vec<CompressedRistretto>>,
        avg_comm_base: &Vec<Vec<RistrettoPoint>>,
        multiplied_ped_sign_bases: &Vec<RistrettoPoint>
    ) -> Result<(), ProofError> {
        let mut transcript = Transcript::new(b"ProofAverageCommitmentG");
        let mut checks = true;
        for (i, a) in proofs.iter().enumerate() {
            for (j, proof) in a.iter().enumerate() {
                checks &= avg_comm_proof::verify_compact(
                    &proof,
                    &mut transcript,
                    avg_comm_proof::VerifyAssignments {
                        A: &avg_comm[i][j],
                        G: &pd_generators.B.compress(),
                        B: &pd_generators.B_blinding.compress(),
                        C: &avg_comm_base[i][j].compress(),
                        H: &multiplied_ped_sign_bases[i].compress(),
                    },
                ).is_ok();
            }
        }
        if checks {
            Ok(())
        }
        else {
            Err(ProofError::VerificationError)
        }
    }

    fn verify_avg(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        proof_average: &Vec<Vec<InnerProductZKProof>>,
        average_commitment: &Vec<Vec<CompressedRistretto>>,
        size_vector: usize
    ) -> Result<(), ProofError> {

        for (i, a) in proof_average.iter().enumerate() {
            for (j, b) in a.iter().enumerate() {
                AvgProof::verify_single(
                    &bp_gens,
                    pc_gens,
                    average_commitment[i][j],
                    b,
                    size_vector)?
            }
        }

        Ok(())
    }

    fn verify_single(
        bp_gens: &BulletproofGens,
        pc_gens: &PedersenGens,
        commitment_sum: CompressedRistretto,
        ip_proof: &InnerProductZKProof,
        size_vector: usize
    ) -> Result<(), ProofError> {
        let mut rng = rand::thread_rng();
        let mut transcript = Transcript::new(b"InnerProductAverage");
        ip_proof.verify_single(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            &commitment_sum,
            size_vector,
            &mut rng
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_addition() {
        let dummy_sensor_values: Vec<[Vec<Scalar>; 3]> = vec![
            [vec![Scalar::from(12u32), Scalar::from(4u32)], vec![Scalar::from(34u32), Scalar::from(4u32)], vec![Scalar::from(122u32), Scalar::from(4u32)]],
            [vec![Scalar::from(4u32), Scalar::from(42345u32)], vec![Scalar::from(234u32), Scalar::from(4u32)], vec![Scalar::from(134u32), Scalar::from(4u32)]],
            [vec![Scalar::from(134u32), Scalar::from(4u32)], vec![Scalar::from(234u32), Scalar::from(4u32)], vec![Scalar::from(1223u32), Scalar::from(4u32)]]
        ];

        let expected_addition: Vec<Vec<Scalar>> = vec![
            vec![Scalar::from(16u32), Scalar::from(38u32), Scalar::from(126u32)],
            vec![Scalar::from(42349u32), Scalar::from(238u32), Scalar::from(138u32)],
            vec![Scalar::from(138u32), Scalar::from(238u32), Scalar::from(1227u32)]
        ];
        let computed_addition: Vec<Vec<Scalar>> =
            AvgProof::compute_sensors_addition(&dummy_sensor_values);

        assert_eq!(expected_addition, computed_addition)
    }
}