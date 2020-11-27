#[allow(non_snake_case)]
use crate::utils::commitment_fns::{multiple_commit};
use crate::utils::misc::*;
use crate::algebraic_proofs::variance_proof::VarianceProof;
use crate::algebraic_proofs::diff_vector_gen_proof::*;
use crate::algebraic_proofs::average_proof::*;

use crate::PedersenVecGens;

use ip_zk_proof::{BulletproofGens, PedersenGens, ProofError};

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{CompressedRistretto};

use rand::thread_rng;
use std::time::{Duration, Instant};

/// This is the prover structure. It will generate a proof that the
/// model was evaluated correctly.
#[derive(Clone)]
pub struct zkSVMProver {
    // Generators used for inner product proofs
    bp_generators: BulletproofGens,
    // Pedersen generators used for single value commitments
    ped_generators: PedersenGens,
    // Commitments signed by the TPM
    signed_commitments: Vec<Vec<CompressedRistretto>>,
    // Diff proofs, containing the diff commitments and the proofs to achieve correctness
    proof_diff: DiffProofs,
    // // Proofs of average computations
    proof_avg: AvgProof,
    // Proof of variance computations (inside is the proof of stds)
    proof_variance: VarianceProof,
    // time computing the hash in millis
    pub hash_computation_time: Duration,
    // Time computing the proof
    pub proof_computation_time: Duration,
    // size of the vectors. this is equal for all sensors
    size: usize,
    // number of sensor elements in each vector. This is different per vector
    size_sensors: Vec<usize>,
}

impl zkSVMProver {
    pub fn new(
        input_vector: &Vec<[Vec<Scalar>; 3]>,
        non_zero_elements: &Vec<usize>,
        diff_vector_scalar: &Vec<[Vec<Scalar>; 3]>,
        additions: &Vec<Vec<Scalar>>,
        variances: &Vec<Vec<Scalar>>,
        sensor_vectors_stds: &Vec<Vec<Scalar>>,
    ) -> Result<zkSVMProver, ProofError> {
        let size_vectors = input_vector[0][0].len();
        let length_all_vectors = input_vector.len();

        // We begin by creating the generators. This should have the option of taking them from an
        // outer source.

        let ped_generators_signature = PedersenVecGens::new(size_vectors);
        let H_vec = PedersenVecGens::new_random(size_vectors);
        let bp_generators = BulletproofGens {
            gens_capacity: size_vectors,
            party_capacity: 1,
            G_vec: vec![ped_generators_signature.clone().B],
            H_vec: vec![H_vec.clone().B],
        };
        let ped_generators = PedersenGens::default();

        // This is performed by the trusted module, but only the prover can have access to the
        // blinding factors. We only hash the initial sensors, which are the first half

        let mut now = Instant::now();
        let all_signed_hash: (Vec<Vec<CompressedRistretto>>, Vec<Vec<Scalar>>) = multiple_commit(
            &ped_generators_signature,
            &input_vector[..(length_all_vectors / 2)].to_vec()
        );
        let hash_computation_time = now.elapsed();
        now = Instant::now();

        // Now we generate the diff_vectors
        let (proof_diff, diff_blindings) = DiffProofs::create(
            &input_vector[..(length_all_vectors / 2)].to_vec(),
            &diff_vector_scalar,
            &all_signed_hash.0,
            &all_signed_hash.1,
            &ped_generators_signature,
            &non_zero_elements
        );

        let add_comm_blinding: Vec<Vec<Scalar>> = (0..length_all_vectors).map(
            |_| (0..3).map(
                |_| Scalar::random(&mut thread_rng())
            ).collect()
        ).collect();

        let mut blind_factors_all_vectors = all_signed_hash.1.clone();
        blind_factors_all_vectors.append(&mut diff_blindings.clone());

        // Now we calculate the average proof
        let average_proof = AvgProof::create(
            &non_zero_elements,
            &bp_generators,
            &ped_generators,
            &input_vector,
            &add_comm_blinding,
            &blind_factors_all_vectors,
        );

        let variance_proof = VarianceProof::create(
            &input_vector,
            &sensor_vectors_stds,
            &additions,
            &variances,
            &bp_generators,
            &ped_generators,
            &ped_generators_signature,
            &H_vec,
            &all_signed_hash.1,
            &diff_blindings,
            &non_zero_elements,
            size_vectors
        )?;


        let proof_computation_time = now.elapsed();

        Ok(zkSVMProver {
            bp_generators: bp_generators,
            ped_generators: ped_generators,
            signed_commitments: all_signed_hash.0,
            proof_diff: proof_diff,
            proof_avg: average_proof,
            proof_variance: variance_proof,
            hash_computation_time: hash_computation_time,
            proof_computation_time: proof_computation_time,
            size: size_vectors,
            size_sensors: non_zero_elements.clone(),
        })
    }

    pub fn hash_init_vectors(ped_gens_signature: PedersenVecGens, all_sensor_vectors: Vec<[Vec<Scalar>; 3]>) -> Vec<Vec<CompressedRistretto>> {
        multiple_commit(
            &ped_gens_signature,
            &all_sensor_vectors
        ).0
    }

    pub fn verify(self) -> Result<(), ProofError>{
        let ped_gens_signature = PedersenVecGens {
            size: self.size,
            B: self.bp_generators.G_vec[0].clone(),
            B_blinding: self.ped_generators.B_blinding
        };

        let H_vec = PedersenVecGens{
            size: self.size,
            B: self.bp_generators.H_vec[0].clone(),
            B_blinding: self.ped_generators.B_blinding
        };

        let mut multiply_ped_sign_acc_bases_G = self.ped_generators.B_blinding;
        for base in self.bp_generators.G_vec[0].clone() {
            multiply_ped_sign_acc_bases_G += &base;
        }

        let mut multiply_ped_acc_bases_H = self.ped_generators.B_blinding;
        for base in self.bp_generators.H_vec[0].clone() {
            multiply_ped_acc_bases_H += &base;
        }

        // Then it generates the diff commitments from the provably iterated commitments
        let diff_commitments: Vec<Vec<CompressedRistretto>> = all_sensors_diff_comm(
            &self.signed_commitments,
            &self.proof_diff.iter_commitments
        );

        self.proof_diff.clone().verify(
                &self.signed_commitments,
                &diff_commitments,
                &ped_gens_signature,
                &self.size_sensors
            )?;

        let length_all_vectors = self.proof_avg.average_commitment.len();
        self.proof_avg.verify(
            &self.bp_generators,
            &self.ped_generators,
            self.size,
            &self.size_sensors
        )?;

        self.proof_variance.verify(
            &self.signed_commitments,
            &diff_commitments,
            &self.proof_diff.last_exp,
            &self.proof_avg.average_commitment_base_G,
            &self.proof_avg.average_commitment_base_H,
            &self.bp_generators,
            &self.ped_generators,
            &ped_gens_signature,
            &H_vec,
            &self.size_sensors,
            self.size,
            length_all_vectors
        )?;

        Ok(())
    }
}