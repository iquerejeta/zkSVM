use num_bigint::{BigInt, Sign};
use curve25519_dalek::scalar::Scalar;
use ip_zk_proof::ProofError;
use pedersen_commitments_proofs::zkSVMProver;


pub fn preprocess_and_prove(
    input_vector: &Vec<[Vec<BigInt>; 3]>,
    non_zero_elements: &Vec<usize>,
    initial_diff_vectors: &Vec<[Vec<BigInt>; 3]>,
    additions: &Vec<Vec<BigInt>>,
    variances: &Vec<Vec<BigInt>>,
    stds: &Vec<Vec<BigInt>>,
) -> Result<zkSVMProver, ProofError> {
    let additions_scalar: Vec<Vec<Scalar>> = additions.iter().map(|x| vec_BigInt_to_scalar(x).unwrap()).collect();
    let variances_scalar: Vec<Vec<Scalar>> = variances.iter().map(|x| vec_BigInt_to_scalar(x).unwrap()).collect();
    let stds_scalar: Vec<Vec<Scalar>> = stds.iter().map(|x| vec_BigInt_to_scalar(x).unwrap()).collect();

    let mut input_vector_scalar: Vec<[Vec<Scalar>; 3]> = Vec::new();
    for arrays in input_vector.iter() {
        let mut new_array = [Vec::new(), Vec::new(), Vec::new()];
        for (index, value) in arrays.iter().enumerate() {
            new_array[index] = vec_BigInt_to_scalar(value)?;
        }
        input_vector_scalar.push(new_array);
    }

    let mut diff_vector_scalar: Vec<[Vec<Scalar>; 3]> = Vec::new();
    for arrays in initial_diff_vectors.iter() {
        let mut new_array = [Vec::new(), Vec::new(), Vec::new()];
        for (index, value) in arrays.iter().enumerate() {
            new_array[index] = vec_BigInt_to_scalar(value)?;
        }
        diff_vector_scalar.push(new_array);
    }

    Ok(zkSVMProver::new(
        &input_vector_scalar,
        non_zero_elements,
        &diff_vector_scalar,
        &additions_scalar,
        &variances_scalar,
        &stds_scalar,
    )?)
}

/// We use this subtraction vector to calculate what we will use as the variance.
/// We need to multiply by the size, because we subtract the addition, and not the average.
/// in this way, the result will not be the variance, but n**3 * variance.
pub fn subtractions_vector(
    non_zero_elements: &Vec<usize>,
    input_vector: &Vec<[Vec<BigInt>; 3]>,
    additions: &Vec<Vec<BigInt>>
) -> Vec<Vec<Vec<BigInt>>> {
    let length = input_vector.len();
    let mut subtractions_vector = vec![Vec::new(); length];
    for i in 0..length {
        for j in 0..3 {
            let mut value_vector: Vec<BigInt> = vec![BigInt::from(0u64); input_vector[i][j].len()];
            for (index, value) in input_vector[i][j][0..non_zero_elements[i]].into_iter().enumerate() {
                value_vector[index] = BigInt::from(non_zero_elements[i] as u64) * value - &additions[i][j];
            }
            subtractions_vector[i].push(value_vector);
        }
    }
    subtractions_vector
}

/// Computes the addition of all inputed vectors
pub fn additions_vector(
    input_vector: &Vec<[Vec<BigInt>; 3]>
) -> Vec<Vec<BigInt>> {
    let mut additions_vector: Vec<Vec<BigInt>> = (0..input_vector.len()).map(
        |_| Vec::new()
    ).collect();
    for (index, vector) in input_vector.iter().enumerate() {
        additions_vector[index] =
            vector
                .iter()
                .map(|x| x.iter().sum())
                .collect();
    }
    additions_vector
}

// Computes the difference of all adjacent values of a vector. Does so for all inputed vectors.
pub fn diff_computation(
    input_vector: &Vec<[Vec<BigInt>; 3]>,
    non_zero_elements: &Vec<usize>,
) -> Vec<[Vec<BigInt>; 3]> {
    let length = input_vector.len();
    let mut diff_computation: Vec<[Vec<BigInt>; 3]> = (0..length).map(
        |_| [Vec::new(), Vec::new(), Vec::new()]
    ).collect();
    for i in 0..length {
        for j in 0..3 {
            diff_computation[i][j] = one_dimesions_diff_computation(&input_vector[i][j], non_zero_elements[i])
        }
    }
    diff_computation
}

// Computes the difference of adjacent values for a single vector
fn one_dimesions_diff_computation(
    coord_vector: &Vec<BigInt>,
    nmbr_non_zero_elements:  usize
) -> Vec<BigInt> {
    let mut diff_vector: Vec<BigInt> = coord_vector.clone();
    for i in 0..(nmbr_non_zero_elements - 1) {
        diff_vector[i] -= &coord_vector[i + 1];
    }
    diff_vector[nmbr_non_zero_elements - 1] -= &coord_vector[0];
    diff_vector
}

// Computes a factor of the variance, mainly Y^3 times the variance, where Y is the number of
// non-zero entries in each vector.
pub fn variance_factor(
    subtracted_values: &Vec<Vec<Vec<BigInt>>>,
) -> Vec<Vec<BigInt>> {
    subtracted_values.iter().map(
        |x| x.iter().map(
            |subtracted_vector| inner_product(&subtracted_vector, &subtracted_vector)
        ).collect()
    ).collect()
}

/// Instead of calculating the standard deviation, we calculate a factor of it. Namely, the square
/// root of the factor of the variance above.
pub fn stds_factor(
    variances: &Vec<Vec<BigInt>>,
) -> Vec<Vec<BigInt>> {
    variances.iter()
        .map(|vectors| vectors.iter()
            .map(|variance| variance.sqrt())
            .collect()
        ).collect()
}

/// Computes an inner product of two vectors
/// \\[
///    {\langle {\mathbf{a}}, {\mathbf{b}} \rangle} = \sum\_{i=0}^{n-1} a\_i \cdot b\_i.
/// \\]
/// Panics if the lengths of \\(\mathbf{a}\\) and \\(\mathbf{b}\\) are not equal.
pub fn inner_product(a: &[BigInt], b: &[BigInt]) -> BigInt {
    let mut out = BigInt::from(0);
    if a.len() != b.len() {
        panic!("inner_product(a,b): lengths of vectors do not match");
    }
    for i in 0..a.len() {
        out += &a[i] * &b[i];
    }
    out
}

pub fn vec_BigInt_to_scalar(input: &Vec<BigInt>) -> Result<Vec<Scalar>, ProofError> {
    Ok(input.into_iter().map(|x| bigInt_to_scalar(x).unwrap()).collect())
}
// Converts a bigInt to scalar
pub fn bigInt_to_scalar(bigInt: &BigInt) -> Result<Scalar, ProofError> {
    let mut buf = [0u8; 64];
    let bytes = bigInt.to_bytes_le();
    if bytes.1.len() > 64 {
        return Err(ProofError::FormatError);
    }

    for (index, &value) in bytes.1.iter().enumerate() {
        buf[index] = value;
    }

    if bigInt.sign() == Sign::Plus {
        return Ok(Scalar::from_bytes_mod_order_wide(&buf))
    }

    else {
        return Ok(-Scalar::from_bytes_mod_order_wide(&buf))
    }
}