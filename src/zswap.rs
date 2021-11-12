use crate::ota::*;
use rand::{Rng, CryptoRng};

pub trait ZSwapScheme: OneTimeAccount {
    type PublicParameters;
    type Signature;
    type State;
    type StateWitness;
    type Error;

    fn setup<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> Result<Self::PublicParameters, Self::Error>;

    fn sign_tx<R: Rng + CryptoRng + ?Sized>(
        params: &Self::PublicParameters,
        inputs: &[(Self::SecretKey, Self::Note, Self::Nullifier, Self::StateWitness, Self::Attributes, Self::Randomness)],
        outputs: &[(Self::PublicKey, Self::Note, Self::Attributes, Self::Randomness)],
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

    fn apply_tx<R: Rng + CryptoRng + ?Sized>(
        state: &mut Self::State,
        transaction: &Transaction<Self>,
    ) -> Result<(), Self::Error> {
        unimplemented!()
    }

    fn receive_tx<R: Rng + CryptoRng + ?Sized>(
        params: &Self::PublicParameters,
        transaction: &Transaction<Self>,
        sk: &[Self::SecretKey],
        rng: &mut R,
    ) -> Result<Vec<(Self::SecretKey, Self::Nullifier, Self::Attributes, Self::Randomness)>, Self::Error> {
        unimplemented!()
    }
}

pub struct Delta {
    pub value: u64,
    pub type_: u64,
    pub is_positive: bool,
}

pub struct Transaction<Z: ZSwapScheme + ?Sized> {
    pub inputs: Vec<Z::Nullifier>,
    pub outputs: Vec<(Z::Note, Z::Ciphertext)>,
    pub deltas: Vec<Delta>,
}

impl<Z: ZSwapScheme + ?Sized> Transaction<Z> {
    pub fn merge(&self, other: &Self) -> Self {
        unimplemented!()
    }
}
