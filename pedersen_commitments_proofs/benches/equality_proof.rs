#![allow(non_snake_case)]
#[macro_use]
extern crate criterion;

use criterion::Criterion;
use pedersen_commitments_proofs::equality_proof::EqualityZKProof;
use pedersen_commitments_proofs::PedersenVecGens;

use curve25519_dalek::scalar::Scalar;

use merlin::Transcript;

use rand_core::OsRng;

fn prove_equality(c: &mut Criterion) {
    let label = format!("Proving equality of openings");
    c.bench_function(&label, move |b| {
        let size = 128;
        let ped_gens_1 = PedersenVecGens::new(size);
        let ped_gens_2 = PedersenVecGens::new_random(size);
        let mut transcript = Transcript::new(b"test");
        let mut csprng: OsRng = OsRng;

        let randomization_1 = Scalar::random(&mut csprng);
        let randomization_2 = Scalar::random(&mut csprng);
        let opening: Vec<Scalar> = (0..size).map(|_| Scalar::random(&mut csprng)).collect();

        b.iter(|| {
            EqualityZKProof::prove_equality(
                &ped_gens_1,
                &ped_gens_2,
                &opening,
                randomization_1,
                randomization_2,
                &mut transcript,
            ).unwrap();
        })
    });
}

fn verify_equality_proof(c: &mut Criterion) {
    let label = format!("Verifying equality proof of openings");
    c.bench_function(&label, move |b| {
        let size = 128;
        let ped_gens_1 = PedersenVecGens::new(size);
        let ped_gens_2 = PedersenVecGens::new_random(size);
        let mut transcript = Transcript::new(b"test");
        let mut csprng: OsRng = OsRng;

        let randomization_1 = Scalar::random(&mut csprng);
        let randomization_2 = Scalar::random(&mut csprng);
        let opening: Vec<Scalar> = (0..size).map(|_| Scalar::random(&mut csprng)).collect();

        let commitment_1 = ped_gens_1.commit(&opening, randomization_1).compress();
        let commitment_2 = ped_gens_2.commit(&opening, randomization_2).compress();

        let proof = EqualityZKProof::prove_equality(
            &ped_gens_1,
            &ped_gens_2,
            &opening,
            randomization_1,
            randomization_2,
            &mut transcript,
        )
        .unwrap();

        b.iter(|| {
            transcript = Transcript::new(b"test");
            proof.clone().verify_equality(
                &ped_gens_1,
                &ped_gens_2,
                commitment_1,
                commitment_2,
                &mut transcript,
            ).unwrap();
        })
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets =
    prove_equality,
    verify_equality_proof
);

criterion_main!(benches);
