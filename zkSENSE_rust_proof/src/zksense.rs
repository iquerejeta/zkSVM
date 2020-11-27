extern crate num_bigint;

use crate::utils::*;
use num_bigint::BigInt;
use pedersen_commitments_proofs::zkSVMProver;
use ip_zk_proof::ProofError;

/// Structure that will encapsulate the zero-knowledge proof of the computations performed to
/// evaluate the SVM in a privacy preserving manner.
#[derive(Clone)]
pub struct zkSVM {
    // Proof of model computation
    pub prover: zkSVMProver,
}


impl zkSVM {
    /// Given the input vectors (to evaluate the SVM model), `create` computes the preprocessing of
    /// the input vectors (mainly the difference, additions, factor of the variance and factor of the
    /// standard deviations), and proves correctness.
    pub fn create(
        // Vector containing sensor data
        input_vector: &Vec<[Vec<BigInt>; 3]>,
        // Number of non-zero elements in the input vector
        non_zero_elements: &Vec<usize>,
    ) -> Result<zkSVM, ProofError> {
        // Compute the difference vectors
        let mut diff_vectors: Vec<[Vec<BigInt>; 3]> = diff_computation(input_vector, &non_zero_elements);

        let initial_diff_vectors = diff_vectors.clone();

        for (index, non_zero_nr) in non_zero_elements.into_iter().enumerate() {
            for i in 0..3 {
                diff_vectors[index][i][non_zero_nr - 1] = BigInt::from(0);
            }
        }

        // We generate the vectors, and their corresponding sizes of non-zero element, over which
        // we evaluate the model
        let mut evaluated_vectors: Vec<[Vec<BigInt>; 3]> = input_vector.clone();
        evaluated_vectors.extend(diff_vectors);

        let mut evaluated_sizes: Vec<usize> = non_zero_elements.clone();
        let diff_sizes: Vec<usize> = non_zero_elements.iter().map(|x| x - 1).collect();
        evaluated_sizes.extend(
            diff_sizes
        );

        let additions = additions_vector(&evaluated_vectors);
        let subtracted_values = subtractions_vector(&non_zero_elements, &input_vector, &additions);
        let variances = variance_factor(&subtracted_values);
        let stds = stds_factor(&variances);

        let prover = preprocess_and_prove(
            &evaluated_vectors,
            &evaluated_sizes,
            &initial_diff_vectors,
            &additions,
            &variances,
            &stds
        )?;

        Ok(zkSVM {prover,})
    }

    pub fn verify(
        self,
    ) -> Result<(), ProofError> {
        self.prover.verify()?;
        return Ok(())
    }
}