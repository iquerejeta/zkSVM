use crate::boolean_proofs::equality_proof::EqualityZKProof;
use crate::boolean_proofs::opening_proof::OpeningZKProof;
use crate::PedersenVecGens;

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};

use merlin::Transcript;
use zkp::CompactProof;

use crate::utils::misc::{generate_permuted_gens, all_sensors_diff_comm};
use crate::utils::commitment_fns::multiple_commit_iter_gens;
use ip_zk_proof::ProofError;

define_proof! {
    dlog,
    "DLog",
    (x),
    (A),
    (G) :
    A = (x * G)
}

/// This proofs allow the user to calculate an iterated commitment of the signed values without
/// having to disclose the actual sensor data.
#[derive(Clone)]
pub struct DiffProofs{
    // Commitments of the iterated opening
    pub iter_commitments: Vec<Vec<CompressedRistretto>>,
    // Proof of the iter commitments
    proof_iter_commitments: Vec<Vec<EqualityZKProof>>,
    // last sensor value of the iterated vector that we need to provably remove
    pub last_exp: Vec<Vec<RistrettoPoint>>,
    // proofs of correctnes
    proofs_last: Vec<Vec<CompactProof>>,
    // Proofs that we know an opening to the remaining commitment with a base missing
    // the last generator
    proof_remove_last: Vec<Vec<OpeningZKProof>>,
}

impl DiffProofs {
    pub fn create(
        sensor_vectors: &Vec<[Vec<Scalar>; 3]>,
        diff_vectors: &Vec<[Vec<Scalar>; 3]>,
        signed_hashes_commitment: &Vec<Vec<CompressedRistretto>>,
        signed_hashes_blinding: &Vec<Vec<Scalar>>,
        ped_vec_generators: &PedersenVecGens,
        size_sensors: &Vec<usize>,
    ) -> (Self, Vec<Vec<Scalar>>) {
        // We permute the bases by one to the left, only until the number of elements that each
        // vector has
        let all_iter_ped_gens = generate_permuted_gens(
            &ped_vec_generators,
            &size_sensors
        );

        // Now we commit the values with the iter base
        let all_hash_iter: (Vec<Vec<CompressedRistretto>>, Vec<Vec<Scalar>>) = multiple_commit_iter_gens(
            &all_iter_ped_gens,
            sensor_vectors
        );

        // We prove correctness
        let prove_iter_generation = prove_equality_commitments(
            &ped_vec_generators,
            &all_iter_ped_gens,
            sensor_vectors,
            &signed_hashes_blinding,
            &all_hash_iter.1
        );
        // Now here we generate the actual diff vectors, by subtracting all_hash_iter to
        // all_signed_hash. Then we need to replace the nth base value (by provably dividing) by
        // a zero.

        let diff_commitments: Vec<Vec<CompressedRistretto>> = all_sensors_diff_comm(
            &signed_hashes_commitment,
            &all_hash_iter.0
        );

        let diff_blindings: Vec<Vec<Scalar>> = (0..4).map(
            |i| (0..3).map(
                |j| &signed_hashes_blinding[i][j] - &all_hash_iter.1[i][j]
            ).collect()
        ).collect();

        let ((last_exp, proofs_last), (_comms_remove_last, proofs_remove_last)) = all_provably_remove_last(
            &ped_vec_generators,
            &diff_vectors,
            &diff_blindings,
            &diff_commitments,
            &size_sensors
        );

        (DiffProofs{
            iter_commitments: all_hash_iter.0,
            proof_iter_commitments: prove_iter_generation,
            last_exp: last_exp,
            proofs_last: proofs_last,
            proof_remove_last: proofs_remove_last,
        }, diff_blindings)
    }

    pub fn verify(
        self,
        signed_commitments: &Vec<Vec<CompressedRistretto>>,
        diff_commitments: &Vec<Vec<CompressedRistretto>>,
        pedersen_generators: &PedersenVecGens,
        size_sensors: &Vec<usize>
    ) -> Result<(), ProofError> {
        // Verifier first generates iterated generators
        let all_iter_ped_gens = generate_permuted_gens(
            pedersen_generators,
            size_sensors
        );

        // And verifies the correctness of both approaches
        verify_proof_equality_commitments(
            pedersen_generators,
            &all_iter_ped_gens,
            signed_commitments,
            &self.iter_commitments,
            &self.proof_iter_commitments
        )?;

        verify_all_proofs_remove_last(
            pedersen_generators,
            diff_commitments,
            &self.last_exp,
            &self.proofs_last,
            &self.proof_remove_last,
            size_sensors
        )?;

        Ok(())
    }
}

fn all_provably_remove_last(
    ped_generators: &PedersenVecGens,
    opening: &Vec<[Vec<Scalar>; 3]>,
    blinding_factors: &Vec<Vec<Scalar>>,
    commitments: &Vec<Vec<CompressedRistretto>>,
    last_non_zeros: &[usize],
) -> ((Vec<Vec<RistrettoPoint>>, Vec<Vec<CompactProof>>), (Vec<Vec<RistrettoPoint>>, Vec<Vec<OpeningZKProof>>)) {
    let nr_sensors = opening.len();
    let mut last_exps = vec![Vec::new(); nr_sensors];
    let mut dlog_proofs = vec![Vec::new(); nr_sensors];
    let mut comms_without_last = vec![Vec::new(); nr_sensors];
    let mut opening_proofs = vec![Vec::new(); nr_sensors];

    for i in 0..nr_sensors {
        for j in 0..3 {
            let ((a, b), (c, d)) = provably_remove_last(
                &ped_generators,
                &opening[i][j],
                blinding_factors[i][j],
                commitments[i][j],
                last_non_zeros[i]
            );
            last_exps[i].push(a);
            dlog_proofs[i].push(b);
            comms_without_last[i].push(c);
            opening_proofs[i].push(d);
        }
    }
    ((last_exps, dlog_proofs), (comms_without_last, opening_proofs))
}

fn verify_all_proofs_remove_last(
    ped_gens: &PedersenVecGens,
    old_comm: &Vec<Vec<CompressedRistretto>>,
    last_exp: &Vec<Vec<RistrettoPoint>>,
    dlog_proof: &Vec<Vec<CompactProof>>,
    opening_proof: &Vec<Vec<OpeningZKProof>>,
    last_non_zeros: &[usize],
) -> Result<(), ProofError> {
    for i in 0..4 {
        for j in 0..3 {
            verify_proof_remove_last(
                &ped_gens,
                old_comm[i][j].decompress().unwrap(),
                last_exp[i][j],
                &dlog_proof[i][j],
                opening_proof[i][j].clone(),
                last_non_zeros[i]
            )?;
        }
    }
    Ok(())
}

fn provably_remove_last(
    ped_generators: &PedersenVecGens,
    opening: &Vec<Scalar>,
    blinding_factor: Scalar,
    commitment: CompressedRistretto,
    last_non_zeros: usize,
) -> ((RistrettoPoint, CompactProof), (RistrettoPoint, OpeningZKProof)) {
    let exp: Scalar = opening[last_non_zeros - 1];
    let last_exp = exp * ped_generators.B[last_non_zeros - 1];
    let mut transcript = Transcript::new(b"ProofRemoveLastNonZeroElement");
    let (proof_last, _) = dlog::prove_compact(
        &mut transcript,
        dlog::ProveAssignments {
            x: &exp,
            A: &last_exp,
            G: &ped_generators.B[last_non_zeros - 1],
        },
    );

    let removed_last = commitment.decompress().unwrap() - last_exp;
    let ped_gens_last = ped_generators.remove_base(&[last_non_zeros - 1]);
    let mut opening_remove_last = opening.clone();
    opening_remove_last.remove(last_non_zeros - 1);
    let proof_opening = OpeningZKProof::prove_opening(
        &ped_gens_last,
        &opening_remove_last,
        blinding_factor,
        &mut transcript
    );

    ((last_exp, proof_last), (removed_last, proof_opening))
}

fn verify_proof_remove_last(
    ped_generators: &PedersenVecGens,
    old_comm: RistrettoPoint,
    last_exp: RistrettoPoint,
    dlog_proof: &CompactProof,
    opening_proof: OpeningZKProof,
    last_non_zeros: usize,
) -> Result<(), ProofError> {
    let ped_gens_last = ped_generators.remove_base(&[last_non_zeros - 1]);
    let comm_remove_last = old_comm - last_exp;

    let mut transcript = Transcript::new(b"ProofRemoveLastNonZeroElement");
    if dlog::verify_compact(
        &dlog_proof,
        &mut transcript,
        dlog::VerifyAssignments {
            A: &last_exp.compress(),
            G: &ped_generators.B[last_non_zeros - 1].compress(),
        },).is_err()
    {
        return Err(ProofError::VerificationError)
    }

    opening_proof.verify_opening_knowledge(
        &ped_gens_last,
        comm_remove_last.compress(),
        &mut transcript)?;

    Ok(())
}

pub fn prove_equality_commitments(
    ped_gens_signature: &PedersenVecGens,
    ped_gens_permuted: &Vec<PedersenVecGens>,
    sensor_vectors: &Vec<[Vec<Scalar>; 3]>,
    blinding_comms_1: &Vec<Vec<Scalar>>,
    blinding_comms_2: &Vec<Vec<Scalar>>
) -> Vec<Vec<EqualityZKProof>> {
    let mut transcript_diff = Transcript::new(b"TranscriptProofDiffCorrectness");

    (0..4).map(
        |i| (0..3).map(
            |j| EqualityZKProof::prove_equality(
                ped_gens_signature,
                &ped_gens_permuted[i],
                &sensor_vectors[i][j],
                blinding_comms_1[i][j],
                blinding_comms_2[i][j],
                &mut transcript_diff
            ).unwrap()
        ).collect()
    ).collect()
}

pub fn verify_proof_equality_commitments(
    ped_gens_signature: &PedersenVecGens,
    ped_gens_permuted: &Vec<PedersenVecGens>,
    commitment_1: &Vec<Vec<CompressedRistretto>>,
    commitment_2: &Vec<Vec<CompressedRistretto>>,
    diff_correctness_proof: &Vec<Vec<EqualityZKProof>>
) -> Result<(), ProofError> {
    let mut transcript_verification = Transcript::new(b"TranscriptProofDiffCorrectness");

    for i in 0..diff_correctness_proof.len() {
        for j in 0..3 {
            diff_correctness_proof[i][j].verify_equality(
                ped_gens_signature,
                &ped_gens_permuted[i],
                commitment_1[i][j],
                commitment_2[i][j],
                &mut transcript_verification
            )?;
        }
    }
    Ok(())
}