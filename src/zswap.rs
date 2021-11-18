use crate::ota::*;
use rand::{CryptoRng, Rng};
use std::collections::{hash_map::Entry, HashMap};

pub trait ZSwapScheme: OneTimeAccount {
    type PublicParameters;
    type Signature;
    type State;
    type StateWitness;
    type Error;

    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self::PublicParameters, Self::Error>;

    fn sign_tx<R: Rng + CryptoRng + Sized>(
        params: &Self::PublicParameters,
        inputs: &[(
            Self::SecretKey,
            Self::Note,
            Self::Nullifier,
            Self::StateWitness,
            Self::Attributes,
            Self::Randomness,
        )],
        outputs: &[(
            Self::PublicKey,
            Self::Note,
            Self::Attributes,
            Self::Randomness,
        )],
        state: &Self::State,
        rng: &mut R,
    ) -> Result<Self::Signature, Self::Error>;

    fn verify_tx<R: Rng + CryptoRng + ?Sized>(
        params: &Self::PublicParameters,
        state: &Self::State,
        transaction: &Transaction<Self>,
        signature: &Self::Signature,
        rng: &mut R,
    ) -> Result<bool, Self::Error>;

    fn apply_input(state: &mut Self::State, input: &Self::Nullifier);

    fn apply_output(state: &mut Self::State, output: &Self::Note);

    fn merge<R: Rng + CryptoRng + ?Sized>(
        params: &Self::PublicParameters,
        signatures: &[Self::Signature],
        rng: &mut R,
    ) -> Result<Self::Signature, Self::Error>;

    fn apply_tx(state: &mut Self::State, transaction: &Transaction<Self>) {
        for input in transaction.inputs.iter() {
            Self::apply_input(state, input);
        }
        for (output, _) in transaction.outputs.iter() {
            Self::apply_output(state, output);
        }
    }

    fn receive_tx(
        transaction: &Transaction<Self>,
        sks: &[Self::SecretKey],
    ) -> Vec<(
        Self::SecretKey,
        Self::Nullifier,
        Self::Attributes,
        Self::Randomness,
    )>
    where
        Self::SecretKey: Clone,
    {
        let mut ret = Vec::new();
        for sk in sks.iter() {
            for (note, ciphertext) in transaction.outputs.iter() {
                if let Some((attribs, r)) = Self::receive(note, ciphertext, sk) {
                    ret.push((sk.clone(), Self::nul_eval(sk, &r), attribs, r));
                }
            }
        }
        ret
    }
}

pub struct Transaction<Z: ZSwapScheme + ?Sized> {
    pub inputs: Vec<Z::Nullifier>,
    pub outputs: Vec<(Z::Note, Z::Ciphertext)>,
    pub deltas: HashMap<u64, i128>,
}

impl<Z: ZSwapScheme + ?Sized> Transaction<Z>
where
    Z::Nullifier: Ord,
    Z::Note: Ord,
    Z::Ciphertext: Ord,
{
    pub fn merge(mut self, other: Self) -> Self {
        self.inputs.extend(other.inputs);
        self.inputs.sort();
        self.outputs.extend(other.outputs);
        self.outputs.sort();
        for (k, v) in other.deltas.into_iter() {
            match self.deltas.entry(k) {
                Entry::Occupied(mut entry) => {
                    *entry.get_mut() += v;
                }
                Entry::Vacant(entry) => {
                    entry.insert(v);
                }
            }
        }
        self
    }
}
