use ip_zk_proof::{BulletproofGens, PedersenGens};
use crate::PedersenVecGens;

/// A structure for Pedersen commitmentts.
#[derive(Clone, Debug)]
pub struct PedersenConfig {
    pedersenGens: PedersenGens,
    G_vec: PedersenVecGens,
    H_vec: PedersenVecGens,
    size: usize
}

impl PedersenConfig {
    pub fn new(
        pedersenGens: &Option<PedersenGens>,
        G_vec: &Option<PedersenVecGens>,
        H_vec: &Option<PedersenVecGens>,
        size: usize,
    ) -> PedersenConfig {
        PedersenConfig{
            pedersenGens: pedersenGens.unwrap_or(PedersenGens::default()),
            G_vec: G_vec.unwrap_or(PedersenVecGens::new(size)),
            H_vec: H_vec.unwrap_or(PedersenVecGens::new_random(size)),
            size
        }
    }

    pub fn get_bp_gens(
        self
    ) -> BulletproofGens {
        BulletproofGens {
            gens_capacity: self.size,
            party_capacity: 1,
            G_vec: vec![self.G_vec.clone().B],
            H_vec: vec![self.H_vec.clone().B],
        }
    }
}