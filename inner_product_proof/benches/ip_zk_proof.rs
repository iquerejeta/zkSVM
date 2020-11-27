#![allow(non_snake_case)]
#[macro_use]
extern crate criterion;
use criterion::Criterion;

use rand_core::OsRng;

use curve25519_dalek::scalar::Scalar;

use merlin::Transcript;

use ip_zk_proof::{InnerProductZKProof, };
use ip_zk_proof::{BulletproofGens, PedersenGens};

static IP_SIZES: [usize; 6] = [4, 8, 16, 32, 64, 128];

fn create_ip_zk_proof(c: &mut Criterion) {
    let label = format!("Generation inner product proof");

    c.bench_function_over_inputs(
        &label,
        move |b, &&n| {
            let pc_gens = PedersenGens::default();
            let bp_gens = BulletproofGens::new(n, 1);
            let mut rng = rand::thread_rng();

            let lhs_ip: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            let rhs_ip: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            let value: Scalar = InnerProductZKProof::inner_product(lhs_ip.clone().as_slice(), rhs_ip.clone().as_slice());

            let v_blinding: Scalar = Scalar::random(&mut rng);
            let a_blinding: Scalar = Scalar::random(&mut rng);

            b.iter(|| {
                // Each proof creation requires a clean transcript.
                let mut transcript = Transcript::new(b"AggregateRangeProofBenchmark");

                InnerProductZKProof::prove_single(
                    &bp_gens,
                    &pc_gens,
                    &mut transcript,
                    value,
                    lhs_ip.clone(),
                    rhs_ip.clone(),
                    v_blinding,
                    a_blinding,
                    n,
                    &mut rng
                )
            })
        },
        &IP_SIZES,
    );
}

fn verify_ip_zk_proof(c: &mut Criterion) {
    let label = format!("Verification inner product proof");

    c.bench_function_over_inputs(
        &label,
        move |b, &&n| {
            let pc_gens = PedersenGens::default();
            let bp_gens = BulletproofGens::new(n, 1);
            let mut rng = rand::thread_rng();

            let lhs_ip: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            let rhs_ip: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            let value: Scalar = InnerProductZKProof::inner_product(lhs_ip.clone().as_slice(), rhs_ip.clone().as_slice());

            let v_blinding: Scalar = Scalar::random(&mut rng);
            let a_blinding: Scalar = Scalar::random(&mut rng);

            let mut transcript = Transcript::new(b"AggregateRangeProofBenchmark");
            let (proof, value_commitments) = InnerProductZKProof::prove_single(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                value,
                lhs_ip,
                rhs_ip,
                v_blinding,
                a_blinding,
                n,
                &mut rng
            )
                .unwrap();

            b.iter(|| {
                // Each proof creation requires a clean transcript.
                let mut transcript = Transcript::new(b"AggregateRangeProofBenchmark");

                proof.verify_single(&bp_gens, &pc_gens, &mut transcript, &value_commitments, n, &mut rng)
            });
        },
        &IP_SIZES,
    );
}

criterion_group! {
    name = create_rp;
    config = Criterion::default().sample_size(10);
    targets =
    create_ip_zk_proof,
}

criterion_group! {
    name = verify_rp;
    config = Criterion::default();
    targets =
    verify_ip_zk_proof,
}

criterion_main!(create_rp, verify_rp);
