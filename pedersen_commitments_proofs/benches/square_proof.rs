#![allow(non_snake_case)]
#[macro_use]
extern crate criterion;

use criterion::Criterion;

use curve25519_dalek::scalar::Scalar;

use merlin::Transcript;

use pedersen_commitments_proofs::square_proof::FloatingSquareZKProof;
use rand::thread_rng;

use ip_zk_proof::{PedersenGens, BulletproofGens};

fn prove_rounded_sqr(c: &mut Criterion) {
    let label = format!("Proving rounded square root relation of commitments");
    c.bench_function(&label, move |b| {
        let bulletproof_generators = BulletproofGens::new(32, 1);
        let pedersen_generators = PedersenGens::default();
        let sq = Scalar::from(12323u64);
        let floor_sqr = Scalar::from(111u64);
        let round_sq = Scalar::from(12321u64);
        let mut transcript = Transcript::new(b"testProofFloorSquare");

        let blinding_sq = Scalar::random(&mut thread_rng());

        let blinding_floor_sqr = Scalar::random(&mut thread_rng());
        let commitment_floor_sqr = pedersen_generators.commit(floor_sqr, blinding_floor_sqr);

        let blinding_round_sq = Scalar::random(&mut thread_rng());

        b.iter(|| {
            FloatingSquareZKProof::create(
                &bulletproof_generators,
                pedersen_generators,
                sq,
                floor_sqr,
                round_sq,
                blinding_sq,
                blinding_floor_sqr,
                blinding_round_sq,
                commitment_floor_sqr.compress(),
                &mut transcript,
            ).unwrap();
        })
    });
}

fn verify_rounded_sqr_proof(c: &mut Criterion) {
    let label = format!("Verifying rounded square root proof");
    c.bench_function(&label, move |b| {
        let bulletproof_generators = BulletproofGens::new(32, 1);
        let pedersen_generators = PedersenGens::default();
        let sq = Scalar::from(12323u64);
        let floor_sqr = Scalar::from(111u64);
        let round_sq = Scalar::from(12321u64);
        let mut transcript = Transcript::new(b"testProofFloorSquare");

        let blinding_sq = Scalar::random(&mut thread_rng());
        let commitment_sq = pedersen_generators.commit(sq, blinding_sq);

        let blinding_floor_sqr = Scalar::random(&mut thread_rng());
        let commitment_floor_sqr = pedersen_generators.commit(floor_sqr, blinding_floor_sqr);

        let blinding_round_sq = Scalar::random(&mut thread_rng());
        let commitment_round_sq = pedersen_generators.commit(round_sq, blinding_round_sq);

        let proof = FloatingSquareZKProof::create(
            &bulletproof_generators,
            pedersen_generators,
            sq,
            floor_sqr,
            round_sq,
            blinding_sq,
            blinding_floor_sqr,
            blinding_round_sq,
            commitment_floor_sqr.compress(),
            &mut transcript,
        ).unwrap();

        b.iter(|| {
            let mut transcript = Transcript::new(b"testProofFloorSquare");
            proof.clone().verify(
                &bulletproof_generators,
                pedersen_generators,
                commitment_floor_sqr.compress(),
                commitment_round_sq.compress(),
                commitment_sq.compress(),
                &mut transcript
            ).unwrap();
        })
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets =
    prove_rounded_sqr,
    verify_rounded_sqr_proof
);

criterion_main!(benches);