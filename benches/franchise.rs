#[macro_use]
extern crate criterion;

use criterion::Criterion;
use halo2_franchise::halo2::pasta::EqAffine;
use halo2_franchise::halo2::plonk::*;
use halo2_franchise::halo2::poly::commitment::Params;
use halo2_franchise::halo2::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use halo2_franchise::{franchise::FranchiseCircuit, utils::generate_test_data};

fn bench<const LVL: usize>(k: u32, c: &mut Criterion) {
    let params: Params<EqAffine> = Params::new(k);
    let empty_circuit = FranchiseCircuit::<LVL>::default();

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let (circuit, public) = generate_test_data::<LVL>();

    let prover_name = format!("franchise-prove-k{}-lvl{}", k, LVL);
    let verifier_name = format!("franchise-verify-k{}-lvl{}", k, LVL);

    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
            create_proof(
                &params,
                &pk,
                &[circuit.clone()],
                &[&[&public]],
                &mut transcript,
            )
            .expect("proof generation should not fail");
            transcript.finalize();
        })
    });

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(&params, &pk, &[circuit], &[&[&public]], &mut transcript)
        .expect("proof generation should not fail");
    let proof = transcript.finalize();

    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let msm = params.empty_msm();
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            let guard =
                verify_proof(&params, pk.get_vk(), msm, &[&[&public]], &mut transcript).unwrap();
            let msm = guard.clone().use_challenges();
            assert!(msm.eval());
        })
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    bench::<9>(9, c);
    bench::<21>(10, c);
}

criterion_group!(benches, criterion_benchmark);

criterion_main!(benches);
