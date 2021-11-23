#![allow(unused_imports)]

use criterion::{criterion_group, criterion_main, Criterion, BatchSize};
use std::time::Duration;
use ark_relations::r1cs::{ConstraintLayer, TracingMode};
use ark_std::UniformRand;
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use std::collections::HashMap;
use tracing_subscriber::layer::SubscriberExt;
use zswap::{Attributes, OneTimeAccount, Transaction, ZSwap, ZSwapScheme, ZSwapState};



fn rand_attr<T:Rng>(rng: &mut T) -> Attributes {
    let type_: u64 = Rng::gen(rng);
    // not too big to allow at least 2^10 merged values.
    let value: u64 = Rng::gen_range(rng, 0..1<<54);

    Attributes{type_, value}
}

fn rand_tx_input<R: Rng + CryptoRng>(
    state: &mut ZSwapState,
    value: Option<u64>,
    type_: Option<u64>,
    rng: &mut R) -> ( <ZSwap as OneTimeAccount>::SecretKey,
                      <ZSwap as OneTimeAccount>::Note,
                      <ZSwap as OneTimeAccount>::Nullifier,
                      <ZSwap as ZSwapScheme>::StateWitness,
                      <ZSwap as OneTimeAccount>::Attributes,
                      <ZSwap as OneTimeAccount>::Randomness) {
    let (pk, sk) = ZSwap::keygen(rng);
    let attr_rand = rand_attr(rng);
    let attr = Attributes{ type_ : type_.unwrap_or(attr_rand.type_),
                           value : value.unwrap_or(attr_rand.value) };
    let r = UniformRand::rand(rng);
    let note = ZSwap::gen(&pk.0, &attr, &r);
    let wit = ZSwap::apply_output(state, &note);
    let nul = ZSwap::nul_eval(&sk, &r);

    (sk.clone(), note.clone(), nul, wit, attr, r)
}

fn rand_tx_output<R: Rng + CryptoRng>(
    value: Option<u64>,
    type_: Option<u64>,
    rng: &mut R) -> ( <ZSwap as OneTimeAccount>::PublicKey,
                      <ZSwap as OneTimeAccount>::Note,
                      <ZSwap as OneTimeAccount>::Ciphertext,
                      <ZSwap as OneTimeAccount>::Attributes,
                      <ZSwap as OneTimeAccount>::Randomness) {
    let (pk, _) = ZSwap::keygen(rng);
    let attr_rand = rand_attr(rng);
    let attr = Attributes{ type_ : type_.unwrap_or(attr_rand.type_),
                           value : value.unwrap_or(attr_rand.value) };
    let r = UniformRand::rand(rng);
    let note = ZSwap::gen(&pk.0, &attr, &r);
    let ciph = ZSwap::enc(&pk, &attr, &r, rng);

    (pk.clone(), note, ciph, attr,r)
}

fn bench_zswap(c: &mut Criterion) {
    let mut grp = c.benchmark_group("ZSwap");

    let mut rng = OsRng;
    let mut rng2 = rand::thread_rng();
    let mut rng3 = OsRng;
    let params = ZSwap::setup(&mut rng).unwrap();
    let mut state = ZSwapState::new();
    let mut state2 = ZSwapState::new();

    grp.bench_function("OTA.keygen", |b| b.iter(|| ZSwap::keygen(&mut rng)));

    grp.bench_function(
        "OTA.gen",
        |b|
        b.iter_batched(|| { let pk = ZSwap::keygen(&mut rng2).0.0;
                            let attr = rand_attr(&mut rng2);
                            let r = UniformRand::rand(&mut rng2);
                            return (pk,attr,r) },
                       |(pk,attr,r)| ZSwap::gen(&pk, &attr, &r),
                       BatchSize::LargeInput));

    grp.bench_function(
        "OTA.enc",
        |b|
        b.iter_batched(|| { let pk = ZSwap::keygen(&mut rng2).0;
                            let attr = rand_attr(&mut rng2);
                            let r = UniformRand::rand(&mut rng2);
                            return (pk,attr,r) },
                       |(pk,attr,r)| ZSwap::enc(&pk, &attr, &r, &mut rng),
                       BatchSize::LargeInput));


    grp.bench_function(
        "OTA.nul_eval",
        |b|
        b.iter_batched(|| { let sk = ZSwap::keygen(&mut rng2).1;
                            let r = UniformRand::rand(&mut rng2);
                            (sk,r) },
                       |(sk,r)| ZSwap::nul_eval(&sk, &r),
                       BatchSize::LargeInput));

    grp.bench_function(
        "sign_tx(1->1)",
        |b|
        b.iter_batched(|| { let input = rand_tx_input(&mut state2,Option::None,Option::None,&mut rng3);
                            let output = rand_tx_output(Option::None,Option::None,&mut rng3);
                            ([input],[output]) },
                       |(input,output)|
                       ZSwap::sign_tx(&params, &input, &output, &mut state, &mut rng),
                       BatchSize::LargeInput));

    grp.finish();
}

criterion_group!(benches, bench_zswap);
criterion_main!(benches);
