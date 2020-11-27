#![allow(non_snake_case)]
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;

use ip_zk_proof::PedersenGens;

use core::iter;
use sha3::Sha3_512;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

/// Represents a pair of base points for Pedersen commitments.
///
/// The Bulletproofs implementation and API is designed to support
/// pluggable bases for Pedersen commitments, so that the choice of
/// bases is not hard-coded.
///
/// The default generators are:
///
/// * `B`: the `ristretto255` basepoint;
/// * `B_blinding`: the result of `ristretto255` SHA3-512
/// hash-to-group on input `B_bytes`.

#[derive(Clone, Debug)]
pub struct PedersenVecGens {
    /// Number of bases
    pub size: usize,
    /// Base for the committed value
    pub B: Vec<RistrettoPoint>,
    /// Base for the blinding factor
    pub B_blinding: RistrettoPoint,
}

impl PedersenVecGens {
    /// Creates a Pedersen commitment using the value scalar and a blinding factor.
    pub fn commit(&self, values: &Vec<Scalar>, blinding: Scalar) -> RistrettoPoint {
        RistrettoPoint::multiscalar_mul(
            iter::once(&blinding).chain(values.iter()),
            iter::once(&self.B_blinding).chain(self.B.iter()),
        )
    }

    pub fn new(size: usize) -> PedersenVecGens {
        let mut generators: Vec<RistrettoPoint> = vec![RISTRETTO_BASEPOINT_POINT];
        for i in 0..(size - 1) {
            generators.push(RistrettoPoint::hash_from_bytes::<Sha3_512>(
                &i.to_be_bytes(),
            ));
        }
        PedersenVecGens {
            size,
            B: generators,
            B_blinding: RistrettoPoint::hash_from_bytes::<Sha3_512>(
                RISTRETTO_BASEPOINT_COMPRESSED.as_bytes(),
            ),
        }
    }

    pub fn new_random(size: usize) -> PedersenVecGens {
        let mut rng = rand::thread_rng();

        let mut generators: Vec<RistrettoPoint> =
            vec![RistrettoPoint::hash_from_bytes::<Sha3_512>(
                &Scalar::random(&mut rng).to_bytes(),
            )];
        for _ in 0..(size - 1) {
            generators.push(RistrettoPoint::hash_from_bytes::<Sha3_512>(
                &Scalar::random(&mut rng).to_bytes(),
            ));
        }
        PedersenVecGens {
            size,
            B: generators,
            B_blinding: RistrettoPoint::hash_from_bytes::<Sha3_512>(
                RISTRETTO_BASEPOINT_COMPRESSED.as_bytes(),
            ),
        }
    }

    /// Iter the generators until 'position' by one position to the left
    /// This is used to prove statements about the 'diff' values in zkSENSE
    pub fn iterate(&self, position: usize) -> PedersenVecGens {
        let mut new_B = self.B.clone();
        new_B[0] = new_B[position - 1];
        for i in 1..position {
            new_B[i] = self.B[i - 1]
        }

        PedersenVecGens {
            size: self.size,
            B: new_B,
            B_blinding: self.B_blinding,
        }
    }

    /// Remove base in positions given by values in input vector
    pub fn remove_base(&self, position: &[usize]) -> PedersenVecGens {
        let mut new_B = self.B.clone();
        for i in position {
            new_B.remove(*i);
        }
        PedersenVecGens {
            size: self.size,
            B: new_B,
            B_blinding: self.B_blinding,
        }
    }
}

impl From<PedersenGens> for PedersenVecGens {
    fn from(generators: PedersenGens) -> Self {
        PedersenVecGens {
            size: 1,
            B: vec![generators.B],
            B_blinding: generators.B_blinding,
        }
    }
}

impl From<Vec<RistrettoPoint>> for PedersenVecGens {
    fn from(generators: Vec<RistrettoPoint>) -> Self {
        PedersenVecGens {
            size: generators.len(),
            B: generators,
            B_blinding: RistrettoPoint::hash_from_bytes::<Sha3_512>(
                RISTRETTO_BASEPOINT_COMPRESSED.as_bytes(),
            ),
        }
    }
}

impl PartialEq for PedersenVecGens {
    fn eq(&self, other: &Self) -> bool {
        self.B == other.B && self.B_blinding == other.B_blinding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_iter() {
        let ped_gens = PedersenVecGens::new(10);

        let iter_ped_gens = ped_gens.clone().iterate(1);

        assert_eq!(ped_gens.clone(), iter_ped_gens);

        let iter_gens = ped_gens.clone().iterate(9);
        let part2_iter_gens = iter_ped_gens.clone().iterate(9);

        assert_eq!(iter_gens, part2_iter_gens);
    }

    #[test]
    fn test_from_pedersen_generators() {
        let ped_gens = PedersenGens::default();
        let opening = Scalar::random(&mut thread_rng());
        let blinding = Scalar::random(&mut thread_rng());

        let ped_vec_gens = PedersenVecGens::from(ped_gens);

        let comm_single = ped_gens.commit(opening, blinding);
        let comm_vec = ped_vec_gens.commit(&vec![opening], blinding);

        assert_eq!(comm_single, comm_vec);
    }
}
