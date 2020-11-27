#![allow(non_snake_case)]
#[macro_use]
extern crate criterion;

use criterion::Criterion;
use pedersen_commitments_proofs::opening_proof::OpeningZKProof;
use pedersen_commitments_proofs::PedersenVecGens;

use curve25519_dalek::scalar::Scalar;

use merlin::Transcript;

use rand_core::OsRng;

fn prove_equality(c: &mut Criterion) {
    let label = format!("Proving opening knowledge of openings");
    c.bench_function(&label, move |b| {
        let size = 128;
        let ped_gens = PedersenVecGens::new(size);
        let mut transcript = Transcript::new(b"test");
        let mut csprng: OsRng = OsRng;

        let randomization = Scalar::random(&mut csprng);
        let opening: Vec<Scalar> = (0..size).map(|_| Scalar::random(&mut csprng)).collect();

        b.iter(|| {
            OpeningZKProof::prove_opening(&ped_gens, &opening, randomization, &mut transcript);
        })
    });
}

fn verify_equality_proof(c: &mut Criterion) {
    let label = format!("Verifying opening knowledge proof of openings");
    c.bench_function(&label, move |b| {
        let size = 128;
        let ped_gens = PedersenVecGens::new(size);
        let mut transcript = Transcript::new(b"test");
        let mut csprng: OsRng = OsRng;

        let randomization = Scalar::random(&mut csprng);
        let opening: Vec<Scalar> = (0..size).map(|_| Scalar::random(&mut csprng)).collect();

        let commitment = ped_gens.commit(&opening, randomization).compress();

        let proof =
            OpeningZKProof::prove_opening(&ped_gens, &opening, randomization, &mut transcript);

        b.iter(|| {
            transcript = Transcript::new(b"test");
            proof.clone()
                .verify_opening_knowledge(&ped_gens, commitment, &mut transcript)
                .unwrap();
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
