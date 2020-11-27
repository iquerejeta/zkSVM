use rand::thread_rng;

use crate::PedersenVecGens;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{CompressedRistretto, };

pub fn multiple_commit_iter_gens(
    ped_vec_generators: &Vec<PedersenVecGens>,
    vectors: &Vec<[Vec<Scalar>; 3]>,
) -> (Vec<Vec<CompressedRistretto>>, Vec<Vec<Scalar>>) {
    let mut commits = Vec::new();
    let mut blindings = Vec::new();
    for i in 0..4 {
        let commitments = hash_sensor_data(
            &ped_vec_generators[i],
            &vectors[i]
        );
        commits.push(commitments.0);
        blindings.push(commitments.1);
    }
    (commits, blindings)
}

pub fn multiple_commit(
    ped_vec_generators: &PedersenVecGens,
    sensor_vectors: &Vec<[Vec<Scalar>; 3]>,
) -> (Vec<Vec<CompressedRistretto>>, Vec<Vec<Scalar>>) {
    let mut commits = Vec::new();
    let mut blindings = Vec::new();
    for i in 0..sensor_vectors.len() {
        let commitments = hash_sensor_data(
            &ped_vec_generators,
            &sensor_vectors[i]
        );
        commits.push(commitments.0);
        blindings.push(commitments.1);
    }
    (commits, blindings)
}

/// Hash sensor data. Return a vector of the points and scalars used for blinding
pub fn hash_sensor_data(
    ped_vec_generators: &PedersenVecGens,
    sensor_vector: &[Vec<Scalar>; 3],
) -> (Vec<CompressedRistretto>, Vec<Scalar>) {

    let blinding_factor: Vec<Scalar> = vec![Scalar::random(&mut thread_rng()); 3];
    ((0..3).map(|index| ped_vec_generators.commit(
        &sensor_vector[index],
        blinding_factor[index]
    ).compress()).collect(), blinding_factor)
}