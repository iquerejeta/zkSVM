use curve25519_dalek::scalar::Scalar;
use crate::PedersenVecGens;
use curve25519_dalek::ristretto::{CompressedRistretto};

/// We use this subtraction vector to calculate what we will use as the variance.
/// We need to multiply by the size, because we subtract the addition, and not the average.
/// in this way, the result will not be the variance, but n**3 * variance.
pub fn compute_subtraction_vector(
    size_sensors: &Vec<usize>,
    sensor_vectors: &Vec<[Vec<Scalar>; 3]>,
    sensor_additions: &Vec<Vec<Scalar>>
) -> Vec<Vec<Vec<Scalar>>> {
    let mut subtraction_vectors = vec![Vec::new(); sensor_vectors.len()];
    for i in 0..sensor_vectors.len() {
        for j in 0..3 {
            let mut value_vector: Vec<Scalar> = vec![Scalar::zero(); sensor_vectors[i][j].len()];
            for (index, value) in sensor_vectors[i][j][0..size_sensors[i]].into_iter().enumerate() {
                value_vector[index] = Scalar::from(size_sensors[i] as u64) * value - sensor_additions[i][j];
            }
            subtraction_vectors[i].push(value_vector);
        }
    }
    subtraction_vectors
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


pub fn generate_permuted_gens(
    ped_vec_generators: &PedersenVecGens,
    number_values: &Vec<usize>
) -> Vec<PedersenVecGens> {
    number_values.iter().map(|&nr| ped_vec_generators.iterate(nr)).collect()
}

pub fn all_sensors_diff_comm(
    signed_comms: &Vec<Vec<CompressedRistretto>>,
    iter_comms: &Vec<Vec<CompressedRistretto>>,
) -> Vec<Vec<CompressedRistretto>> {
    (0..4).map(
        |i| (0..3).map(
            |j| (signed_comms[i][j].decompress().unwrap() - iter_comms[i][j].decompress().unwrap()).compress()
        ).collect()
    ).collect()
}

pub fn diff_computation(
    input_vector: &Vec<[Vec<Scalar>; 3]>,
    nmbr_nonzero_elements: &Vec<usize>,
) -> Vec<[Vec<Scalar>; 3]> {
    let nr_sensors = input_vector.len();
    let mut diff_vectors: Vec<[Vec<Scalar>; 3]> = (0..nr_sensors).map(
        |_| [Vec::new(), Vec::new(), Vec::new()]
    ).collect();
    for i in 0..nr_sensors {
        for j in 0..3 {
            diff_vectors[i][j] = one_coord_diff_value(&input_vector[i][j], nmbr_nonzero_elements[i])
        }
    }
    diff_vectors
}

fn one_coord_diff_value(
    coord_vector: &Vec<Scalar>,
    nmbr_non_zero_elements:  usize
) -> Vec<Scalar> {
    let mut diff_vector: Vec<Scalar> = coord_vector.clone();
    for i in 0..(nmbr_non_zero_elements - 1) {
        diff_vector[i] -= &coord_vector[i + 1];
    }
    diff_vector[nmbr_non_zero_elements - 1] -= &coord_vector[0];
    diff_vector
}

