use crate::ota::*;
use rand::{CryptoRng, Rng};
use std::collections::{hash_map::Entry, HashMap};


pub type ZSwapInput<Z> = (
    <Z as OneTimeAccount>::SecretKey,
    <Z as OneTimeAccount>::Note,
    <Z as OneTimeAccount>::Nullifier,
    <Z as ZSwapScheme>::StateWitness,
    <Z as OneTimeAccount>::Attributes,
    <Z as OneTimeAccount>::Randomness);

pub type ZSwapOutput<Z> = (
    <Z as OneTimeAccount>::PublicKey,
    <Z as OneTimeAccount>::Note,
    <Z as OneTimeAccount>::Ciphertext,
    <Z as OneTimeAccount>::Attributes,
    <Z as OneTimeAccount>::Randomness);

pub trait ZSwapScheme: OneTimeAccount {
    type PublicParameters;
    type Signature;
    type State;
    type StateWitness;
    type Error;

    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self::PublicParameters, Self::Error>;

    fn sign_tx<R: Rng + CryptoRng + Sized>(
        params: &Self::PublicParameters,
        inputs: &[ZSwapInput<Self>],
        outputs: &[ZSwapOutput<Self>],
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

    fn apply_output(state: &mut Self::State, output: &Self::Note) -> Self::StateWitness;

    fn merge<R: Rng + CryptoRng + ?Sized>(
        params: &Self::PublicParameters,
        signatures: &[Self::Signature],
        rng: &mut R,
    ) -> Result<Self::Signature, Self::Error>;

    fn apply_tx(
        state: &mut Self::State,
        transaction: &Transaction<Self>,
    ) -> Vec<Self::StateWitness> {
        for input in transaction.inputs.iter() {
            Self::apply_input(state, input);
        }
        let mut out = Vec::with_capacity(transaction.outputs.len());
        for (output, _) in transaction.outputs.iter() {
            out.push(Self::apply_output(state, output));
        }
        out
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
    pub fn normalise(&mut self) {
        self.inputs.sort();
        self.outputs.sort();
    }


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
        self.deltas.retain(|_, v| v != &0);
        self
    }
}
