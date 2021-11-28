use ark_relations::r1cs::{ConstraintLayer, TracingMode};
use ark_std::UniformRand;
use rand::rngs::OsRng;
use std::collections::HashMap;
use tracing_subscriber::layer::SubscriberExt;
use zswap::{Attributes, OneTimeAccount, Transaction, ZSwap, ZSwapScheme, ZSwapState};
use std::time::Instant;

#[macro_use]
extern crate log;

fn main() {
    env_logger::init();

    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::All;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let mut rng = OsRng;
    info!("param generation");
    let params = ZSwap::setup(&mut rng).unwrap();
    info!("\tdone");
    info!("genesis setup");
    let (pk_alice, sk_alice) = ZSwap::keygen(&mut rng);
    let (pk_bob, sk_bob) = ZSwap::keygen(&mut rng);

    const RED: u64 = 0;
    const BLUE: u64 = 1;

    let genesis_red_rnd = UniformRand::rand(&mut rng);
    let genesis_red_attribs = Attributes {
        type_: RED,
        value: 20,
    };
    let genesis_red = ZSwap::gen(&pk_alice.0, &genesis_red_attribs, &genesis_red_rnd);

    let genesis_blue_rnd = UniformRand::rand(&mut rng);
    let genesis_blue_attribs = Attributes {
        type_: BLUE,
        value: 30,
    };
    let genesis_blue = ZSwap::gen(&pk_alice.0, &genesis_blue_attribs, &genesis_blue_rnd);

    let mut state = ZSwapState::new();
    let genesis_red_wit = ZSwap::apply_output(&mut state, &genesis_red);
    let genesis_blue_wit = ZSwap::apply_output(&mut state, &genesis_blue);
    info!("\tdone");

    info!("tx1 creation");
    let tx1_inputs = [(
        sk_alice.clone(),
        genesis_red.clone(),
        ZSwap::nul_eval(&sk_alice, &genesis_red_rnd),
        genesis_red_wit,
        genesis_red_attribs,
        genesis_red_rnd,
    )];
    let tx1_output1_rnd = UniformRand::rand(&mut rng);
    let tx1_output1_attribs = Attributes {
        type_: RED,
        value: 10,
    };
    let tx1_output1 = ZSwap::gen(&pk_bob.0, &tx1_output1_attribs, &tx1_output1_rnd);
    let tx1_output1_ciph = ZSwap::enc(&pk_bob, &tx1_output1_attribs, &tx1_output1_rnd, &mut rng);
    let tx1_output2_rnd = UniformRand::rand(&mut rng);
    let tx1_output2_attribs = Attributes {
        type_: RED,
        value: 10,
    };
    let tx1_output2 = ZSwap::gen(&pk_alice.0, &tx1_output2_attribs, &tx1_output2_rnd);
    let tx1_output2_ciph = ZSwap::enc(&pk_alice, &tx1_output2_attribs, &tx1_output2_rnd, &mut rng);
    let tx1_outputs = [
        (
            pk_bob.clone(),
            tx1_output1,
            tx1_output1_ciph,
            tx1_output1_attribs.clone(),
            tx1_output1_rnd.clone(),
        ),
        (
            pk_alice.clone(),
            tx1_output2,
            tx1_output2_ciph,
            tx1_output2_attribs,
            tx1_output2_rnd,
        ),
    ];
    let tx1_sig = ZSwap::sign_tx(&params, &tx1_inputs, &tx1_outputs, &state, &mut rng).unwrap();
    let mut tx1_deltas = HashMap::new();
    tx1_deltas.insert(RED, 0);
    let mut tx1 = Transaction::<ZSwap> {
        inputs: tx1_inputs.into_iter().map(|i| i.2).collect(),
        outputs: tx1_outputs.into_iter().map(|o| (o.1, o.2)).collect(),
        deltas: tx1_deltas,
    };
    tx1.normalise();
    info!("\tdone");

    info!("tx1 verification");
    assert!(ZSwap::verify_tx(&params, &state, &tx1, &tx1_sig, &mut rng).unwrap());
    let wits = ZSwap::apply_tx(&mut state, &tx1);
    let tx1_output1_wit = wits[tx1.outputs.iter().position(|elem| elem.0 == tx1_output1).unwrap()];
    info!("\tdone");

    // Now: Alice has 10 RED, 30 BLUE, Bob has 10 RED
    //
    // We will set up a swap: Alice offers 20 blue for 5 red, and Bob makes the counter offer.
    // Merge and verify.

    info!("tx2 creation");
    let tx2_inputs = [(
        sk_alice.clone(),
        genesis_blue.clone(),
        ZSwap::nul_eval(&sk_alice, &genesis_blue_rnd),
        genesis_blue_wit,
        genesis_blue_attribs,
        genesis_blue_rnd,
    )];
    let tx2_output1_rnd = UniformRand::rand(&mut rng);
    let tx2_output1_attribs = Attributes {
        type_: BLUE,
        value: 10,
    };
    let tx2_output1 = ZSwap::gen(&pk_alice.0, &tx2_output1_attribs, &tx2_output1_rnd);
    let tx2_output1_ciph = ZSwap::enc(&pk_alice, &tx2_output1_attribs, &tx2_output1_rnd, &mut rng);
    let tx2_output2_rnd = UniformRand::rand(&mut rng);
    let tx2_output2_attribs = Attributes {
        type_: RED,
        value: 5,
    };
    let tx2_output2 = ZSwap::gen(&pk_alice.0, &tx2_output2_attribs, &tx2_output2_rnd);
    let tx2_output2_ciph = ZSwap::enc(&pk_alice, &tx2_output2_attribs, &tx2_output2_rnd, &mut rng);
    let tx2_outputs = [
        (
            pk_alice.clone(),
            tx2_output1,
            tx2_output1_ciph,
            tx2_output1_attribs,
            tx2_output1_rnd,
        ),
        (
            pk_alice.clone(),
            tx2_output2,
            tx2_output2_ciph,
            tx2_output2_attribs,
            tx2_output2_rnd,
        ),
    ];
    let tx2_sig = ZSwap::sign_tx(&params, &tx2_inputs, &tx2_outputs, &state, &mut rng).unwrap();
    let mut tx2_deltas = HashMap::new();
    tx2_deltas.insert(BLUE, 20);
    tx2_deltas.insert(RED, -5);
    let mut tx2 = Transaction::<ZSwap> {
        inputs: tx2_inputs.into_iter().map(|i| i.2).collect(),
        outputs: tx2_outputs.into_iter().map(|o| (o.1, o.2)).collect(),
        deltas: tx2_deltas,
    };
    tx2.normalise();
    info!("\tdone");
    info!("tx2 verification");
    assert!(ZSwap::verify_tx(&params, &state, &tx2, &tx2_sig, &mut rng).unwrap());
    info!("\tdone");

    info!("tx3 creation");
    let tx3_inputs = [(
        sk_bob.clone(),
        tx1_output1.clone(),
        ZSwap::nul_eval(&sk_bob, &tx1_output1_rnd),
        tx1_output1_wit,
        tx1_output1_attribs,
        tx1_output1_rnd,
    )];
    let tx3_output1_rnd = UniformRand::rand(&mut rng);
    let tx3_output1_attribs = Attributes {
        type_: RED,
        value: 5,
    };
    let tx3_output1 = ZSwap::gen(&pk_bob.0, &tx3_output1_attribs, &tx3_output1_rnd);
    let tx3_output1_ciph = ZSwap::enc(&pk_alice, &tx3_output1_attribs, &tx3_output1_rnd, &mut rng);
    let tx3_output2_rnd = UniformRand::rand(&mut rng);
    let tx3_output2_attribs = Attributes {
        type_: BLUE,
        value: 20,
    };
    let tx3_output2 = ZSwap::gen(&pk_bob.0, &tx3_output2_attribs, &tx3_output2_rnd);
    let tx3_output2_ciph = ZSwap::enc(&pk_alice, &tx3_output2_attribs, &tx3_output2_rnd, &mut rng);
    let tx3_outputs = [
        (
            pk_bob.clone(),
            tx3_output1,
            tx3_output1_ciph,
            tx3_output1_attribs,
            tx3_output1_rnd,
        ),
        (
            pk_bob.clone(),
            tx3_output2,
            tx3_output2_ciph,
            tx3_output2_attribs,
            tx3_output2_rnd,
        ),
    ];
    let tx3_sig = ZSwap::sign_tx(&params, &tx3_inputs, &tx3_outputs, &state, &mut rng).unwrap();
    let mut tx3_deltas = HashMap::new();
    tx3_deltas.insert(RED, 5);
    tx3_deltas.insert(BLUE, -20);
    let mut tx3 = Transaction::<ZSwap> {
        inputs: tx3_inputs.into_iter().map(|i| i.2).collect(),
        outputs: tx3_outputs.into_iter().map(|o| (o.1, o.2)).collect(),
        deltas: tx3_deltas,
    };
    tx3.normalise();
    info!("\tdone");
    info!("tx3 verification");
    assert!(ZSwap::verify_tx(&params, &state, &tx3, &tx3_sig, &mut rng).unwrap());
    info!("\tdone");

    info!("tx merge");
    let t0 = Instant::now();
    let tx4 = tx2.merge(tx3);
    let tx4_sig = ZSwap::merge(&params, &[tx2_sig, tx3_sig], &mut rng).unwrap();
    info!("\tMerging signature and tx took {}μs", Instant::now().duration_since(t0).as_micros());
    info!("\tdone");
    info!("merge verification");
    assert!(ZSwap::verify_tx(&params, &state, &tx4, &tx4_sig, &mut rng).unwrap());
    assert!(tx4.deltas.is_empty());
    info!("\tdone");
}
