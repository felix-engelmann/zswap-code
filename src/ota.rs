use ark_ff::fields::Field;
use ark_ff::UniformRand;
use ark_r1cs_std::alloc::AllocVar;
use ark_relations;
use ark_relations::r1cs::SynthesisError;
use rand::{CryptoRng, Rng};

pub trait OneTimeAccount {
    type SecretKey;
    type PublicKey;
    type PartialPublicKey;
    type Randomness: UniformRand;
    type Attributes;
    type Note;
    type Ciphertext;
    type Nullifier;

    fn keygen<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey);
    fn derive_public_key(sk: &Self::SecretKey) -> Self::PartialPublicKey;
    fn gen(
        pk: &Self::PartialPublicKey,
        attribs: &Self::Attributes,
        r: &Self::Randomness,
    ) -> Self::Note;
    fn enc<R: Rng + CryptoRng + ?Sized>(
        pk: &Self::PublicKey,
        attribs: &Self::Attributes,
        r: &Self::Randomness,
        rng: &mut R,
    ) -> Self::Ciphertext;
    fn receive(
        note: &Self::Note,
        ciph: &Self::Ciphertext,
        sk: &Self::SecretKey,
    ) -> Option<(Self::Attributes, Self::Randomness)>;
    fn nul_eval(sk: &Self::SecretKey, r: &Self::Randomness) -> Self::Nullifier;
}

pub trait OTAGadget<F: Field>: OneTimeAccount {
    type KeyDeriveParams;
    type GenParams;
    type TagEvalParams;
    type SecretKeyVar: AllocVar<Self::SecretKey, F>;
    type PublicKeyVar: AllocVar<Self::PartialPublicKey, F>;
    type RandomnessVar: AllocVar<Self::Randomness, F>;
    type AttributesVar: AllocVar<Self::Attributes, F>;
    type NoteVar: AllocVar<Self::Note, F>;
    type NullifierVar: AllocVar<Self::Nullifier, F>;

    fn derive_public_key_gadget(
        params: &Self::KeyDeriveParams,
        sk: &Self::SecretKeyVar,
    ) -> Result<Self::PublicKeyVar, SynthesisError>;
    fn gen_gadget(
        params: &Self::GenParams,
        pk: &Self::PublicKeyVar,
        attribs: &Self::AttributesVar,
        r: &Self::RandomnessVar,
    ) -> Result<Self::NoteVar, SynthesisError>;
    fn nul_eval_gadget(
        params: &Self::TagEvalParams,
        sk: &Self::SecretKeyVar,
        r: &Self::RandomnessVar,
    ) -> Result<Self::NullifierVar, SynthesisError>;
}
