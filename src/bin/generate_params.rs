use ark_std::UniformRand;
use rand::rngs::OsRng;
use std::collections::HashMap;
use zswap_code::{Attributes, OneTimeAccount, Transaction, ZSwap, ZSwapScheme, ZSwapState};

fn main() {
    env_logger::init();
    let mut rng = OsRng;
    let params = ZSwap::setup(&mut rng).unwrap();
    println!("params generated!");
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
    let path_genesis_red = ZSwap::apply_output(&mut state, &genesis_red);
    let path_genesis_blue = ZSwap::apply_output(&mut state, &genesis_blue);

    let tx1_inputs = [(
        sk_alice.clone(),
        genesis_red.clone(),
        ZSwap::nul_eval(&sk_alice, &genesis_red_rnd),
        path_genesis_red,
        genesis_red_attribs,
        genesis_red_rnd,
    )];
    let tx1_output_1_rnd = UniformRand::rand(&mut rng);
    let tx1_output_1_attribs = Attributes {
        type_: RED,
        value: 10,
    };
    let tx1_output_1 = ZSwap::gen(&pk_bob.0, &tx1_output_1_attribs, &tx1_output_1_rnd);
    let tx1_output_1_ciph = ZSwap::enc(&pk_bob, &tx1_output_1_attribs, &tx1_output_1_rnd, &mut rng);
    let tx1_output_2_rnd = UniformRand::rand(&mut rng);
    let tx1_output_2_attribs = Attributes {
        type_: RED,
        value: 10,
    };
    let tx1_output_2 = ZSwap::gen(&pk_alice.0, &tx1_output_2_attribs, &tx1_output_2_rnd);
    let tx1_output_2_ciph = ZSwap::enc(&pk_bob, &tx1_output_2_attribs, &tx1_output_2_rnd, &mut rng);
    let tx1_outputs = [
        (
            pk_bob.clone(),
            tx1_output_1,
            tx1_output_1_ciph,
            tx1_output_1_attribs,
            tx1_output_1_rnd,
        ),
        (
            pk_alice.clone(),
            tx1_output_2,
            tx1_output_2_ciph,
            tx1_output_2_attribs,
            tx1_output_2_rnd,
        ),
    ];
    let tx1_sig = ZSwap::sign_tx(&params, &tx1_inputs, &tx1_outputs, &state, &mut rng).unwrap();
    let mut tx1_deltas = HashMap::new();
    tx1_deltas.insert(RED, 0);
    let tx1 = Transaction::<ZSwap> {
        inputs: tx1_inputs.into_iter().map(|i| i.2).collect(),
        outputs: tx1_outputs.into_iter().map(|o| (o.1, o.2)).collect(),
        deltas: tx1_deltas,
    };

    assert!(ZSwap::verify_tx(&params, &state, &tx1, &tx1_sig, &mut rng).unwrap());
}
