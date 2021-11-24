#![allow(unused_imports)]

use criterion::{criterion_group, criterion_main, Criterion, BatchSize};
use std::time::Duration;
use ark_relations::r1cs::{ConstraintLayer, TracingMode};
use ark_std::UniformRand;
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use std::collections::HashMap;
use tracing_subscriber::layer::SubscriberExt;
use zswap::{Attributes, ZSwapInput, ZSwapOutput,
            OneTimeAccount, Transaction, ZSwap, ZSwapScheme, ZSwapState};



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
    rng: &mut R) -> ZSwapInput<ZSwap> {
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
    rng: &mut R) -> ZSwapOutput<ZSwap> {
    let (pk, _) = ZSwap::keygen(rng);
    let attr_rand = rand_attr(rng);
    let attr = Attributes{ type_ : type_.unwrap_or(attr_rand.type_),
                           value : value.unwrap_or(attr_rand.value) };
    let r = UniformRand::rand(rng);
    let note = ZSwap::gen(&pk.0, &attr, &r);
    let ciph = ZSwap::enc(&pk, &attr, &r, rng);

    (pk.clone(), note, ciph, attr,r)
}

pub fn from_input_output(inputs: &[ZSwapInput<ZSwap>],
                         outputs: &[ZSwapOutput<ZSwap>]) -> Transaction<ZSwap> {
    let mut deltas = HashMap::new();
    for input in inputs {
        let t: u64 = input.4.type_;
        let v: u64 = input.4.value;
        if let Some(x) = deltas.get_mut(&t) {
            *x = *x + (v as i128);
        } else { deltas.insert(t, v as i128); }
    }
    for output in outputs {
        let t: u64 = output.3.type_;
        let v: u64 = output.3.value;
        if let Some(x) = deltas.get_mut(&t) {
            *x = *x - (v as i128);
        } else { deltas.insert(t, -(v as i128)); }
    }

    let mut tx = Transaction::<ZSwap> {
        inputs: inputs.into_iter().map(|i| i.2).collect(),
        outputs: outputs.into_iter().map(|o| (o.1, o.2.clone())).collect(),
        deltas: deltas,
    };
    tx.normalise();

    tx
}

fn rand_tx_1in_1out<R: Rng + CryptoRng>(
    params: &<ZSwap as ZSwapScheme>::PublicParameters,
    state: &mut <ZSwap as ZSwapScheme>::State,
    rng: &mut R) -> (Transaction<ZSwap>,<ZSwap as ZSwapScheme>::Signature) {
    let inputs = &[rand_tx_input(state,Option::None,Option::None,rng)];
    let outputs = &[rand_tx_output(Option::None,Option::None,rng)];
    let sig = ZSwap::sign_tx(params, inputs, outputs, state, rng).unwrap();
    let tx = from_input_output(inputs, outputs);

    (tx,sig)
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

    // @volhovm: I have a suspicion this is faster than it should be.
    grp.bench_function(
        "sign_tx(1->1)",
        |b|
        b.iter_batched(|| { let input = rand_tx_input(&mut state2,Option::None,Option::None,&mut rng3);
                            let output = rand_tx_output(Option::None,Option::None,&mut rng3);
                            ([input],[output]) },
                       |(input,output)|
                       ZSwap::sign_tx(&params, &input, &output, &mut state, &mut rng),
                       BatchSize::LargeInput));

    // @volhovm: I have a suspicion this is faster than it should be.
    grp.bench_function(
        "build_tx(1->1)",
        |b|
        b.iter_batched(|| { let input = rand_tx_input(&mut state2,Option::None,Option::None,&mut rng3);
                            let output = rand_tx_output(Option::None,Option::None,&mut rng3);
                            ([input],[output]) },
                       |(inputs,outputs)| from_input_output(&inputs,&outputs),
                       BatchSize::LargeInput));

    grp.bench_function(
        "merge (1->1)&(1->1)",
        |b|
        b.iter_batched(|| {
            let tx1 = rand_tx_1in_1out(&params, &mut state2,&mut rng2);
            let tx2 = rand_tx_1in_1out(&params, &mut state2,&mut rng2);
            (tx1,tx2) },
                       |(tx1,tx2)| ZSwap::merge(&params, &[tx1.1, tx2.1], &mut rng).unwrap(),
                       BatchSize::LargeInput));


    grp.finish();
}

criterion_group!(benches, bench_zswap);
criterion_main!(benches);
