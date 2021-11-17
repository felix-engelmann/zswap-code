use ark_crypto_primitives::merkle_tree::{self, LeafParam, TwoToOneParam};
use ark_ec::models::twisted_edwards_extended::GroupAffine;
use ark_ec::models::TEModelParameters;
use ark_ff::fields::PrimeField;
use ark_nonnative_field::NonNativeFieldVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_relations::r1cs::SynthesisError;
#[cfg(test)]
use rand::thread_rng;
use rand::{CryptoRng, Rng};
use std::marker::PhantomData;
use std::ops::{Add, Neg, Sub};

pub trait EncryptionScheme {
    type SecretKey;
    type PublicKey;

    fn keygen<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey);
    fn encrypt<R: Rng + CryptoRng + ?Sized>(
        to: &Self::PublicKey,
        msg: &[u8],
        rng: &mut R,
    ) -> Vec<u8>;
    fn decrypt(with: &Self::SecretKey, ciph: &[u8]) -> Option<Vec<u8>>;
}

pub trait CompressionFunction<F> {
    fn compress(a: &F, b: &F) -> F;
}

pub trait CompressionFunctionGadget<F> {
    type ParametersVar;

    fn compress(params: &Self::ParametersVar, a: &F, b: &F) -> Result<F, SynthesisError>;
}

pub trait CommitmentScheme<F> {
    // It seems this is the structure all of our commitments follow?
    fn commit(x: (&F, &F), r: &F) -> F;
}

impl<F, T> CommitmentScheme<F> for T
where
    T: CompressionFunction<F>,
{
    fn commit((a, b): (&F, &F), r: &F) -> F {
        Self::compress(&Self::compress(a, b), r)
    }
}

pub trait CommitmentSchemeGadget<F> {
    type ParametersVar;

    fn commit(params: &Self::ParametersVar, x: (&F, &F), r: &F) -> Result<F, SynthesisError>;
}

impl<F, T> CommitmentSchemeGadget<F> for T
where
    T: CompressionFunctionGadget<F>,
{
    type ParametersVar = <Self as CompressionFunctionGadget<F>>::ParametersVar;

    fn commit(params: &Self::ParametersVar, (a, b): (&F, &F), r: &F) -> Result<F, SynthesisError> {
        Self::compress(params, &Self::compress(params, a, b)?, r)
    }
}

pub trait HomomorphicCommitmentScheme<T, V, R>
where
    V: Eq + Add<Output = V> + Sub<Output = V> + Neg<Output = V>,
    R: Eq + Add<Output = R> + Sub<Output = R> + Neg<Output = R>,
{
    type Commitment: Eq
        + Add<Output = Self::Commitment>
        + Sub<Output = Self::Commitment>
        + Neg<Output = Self::Commitment>;
    type TypeWitness;

    /// Must be such that:
    /// a) Summed commitments should verify against their summed randomness.
    /// b) Summed commitments should be equal to a sum of (for each type) the value sum.
    fn commit(type_: &T, v: &V, r: &R) -> (Self::Commitment, Self::TypeWitness);
    fn verify(type_: &T, wit: &Self::TypeWitness, v: &V, r: &R) -> Option<Self::Commitment>;
}

pub trait HomomorphicCommitmentSchemeGadget<F: PrimeField, T, V, R>
where
    V: EqGadget<F> + Add<Output = V> + Sub<Output = V>,
    R: EqGadget<F> + Add<Output = R> + Sub<Output = R>,
{
    type ParametersVar;
    type CommitmentVar: EqGadget<F>
        + Add<Output = Self::CommitmentVar>
        + Sub<Output = Self::CommitmentVar>;
    type TypeWitnessVar;

    fn verify(
        type_: &T,
        wit: &Self::TypeWitnessVar,
        v: &V,
        r: &R,
        com: &Self::CommitmentVar,
    ) -> Result<(), SynthesisError>;
}

pub struct MultiBasePedersen<P: TEModelParameters, H>(pub PhantomData<(P, H)>)
where
    P::BaseField: PrimeField;

// Basic idea: Our type `type_: P::BaseField` is combined with a counter `ctr: P::BaseField` using
// a two-to-one hash. The result should be in `x: P::ScalarField` (conversion check needed). Find
// `y: P::ScalarField` such that `(x, y)` is a valid curve point. `(ctr, y)` are witnesses to
// `type_`.
#[allow(unused_variables)]
impl<P: TEModelParameters, H: CompressionFunction<P::BaseField>>
    HomomorphicCommitmentScheme<P::BaseField, P::ScalarField, P::ScalarField>
    for MultiBasePedersen<P, H>
where
    P::BaseField: PrimeField,
{
    type Commitment = GroupAffine<P>;
    type TypeWitness = (P::BaseField, P::ScalarField);

    fn commit(
        type_: &P::BaseField,
        v: &P::ScalarField,
        r: &P::ScalarField,
    ) -> (Self::Commitment, Self::TypeWitness) {
        unimplemented!()
    }

    fn verify(
        type_: &P::BaseField,
        wit: &Self::TypeWitness,
        v: &P::ScalarField,
        r: &P::ScalarField,
    ) -> Option<Self::Commitment> {
        unimplemented!()
    }
}

// FIXME: Aligning FpVar<F> and FpVar<P::BaseField> is a pain! Even though they are ostensibly the
// same...
#[allow(unused_variables)]
impl<P: TEModelParameters, H: CompressionFunctionGadget<P::BaseField>>
    HomomorphicCommitmentSchemeGadget<
        P::BaseField,
        FpVar<P::BaseField>,
        NonNativeFieldVar<P::ScalarField, P::BaseField>,
        NonNativeFieldVar<P::ScalarField, P::BaseField>,
    > for MultiBasePedersen<P, H>
where
    P::BaseField: PrimeField,
{
    type ParametersVar = <H as CompressionFunctionGadget<P::BaseField>>::ParametersVar;
    type CommitmentVar = AffineVar<P, FpVar<P::BaseField>>;
    type TypeWitnessVar = (
        FpVar<P::BaseField>,
        NonNativeFieldVar<P::ScalarField, P::BaseField>,
    );

    fn verify(
        type_: &FpVar<P::BaseField>,
        wit: &Self::TypeWitnessVar,
        v: &NonNativeFieldVar<P::ScalarField, P::BaseField>,
        r: &NonNativeFieldVar<P::ScalarField, P::BaseField>,
        com: &Self::CommitmentVar,
    ) -> Result<(), SynthesisError> {
        unimplemented!()
    }
}

pub trait MerkleTreeParams<F> {
    type Config: merkle_tree::Config<Leaf = [F], LeafDigest = F, InnerDigest = F>;

    fn leaf_param() -> &'static LeafParam<Self::Config>;
    fn compression_param() -> &'static TwoToOneParam<Self::Config>;
}

pub struct ECIES;

impl EncryptionScheme for ECIES {
    type SecretKey = [u8; 32];
    type PublicKey = [u8; 65];

    fn keygen<R: Rng + CryptoRng + ?Sized>(_rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        let (sk, pk) = ecies::utils::generate_keypair();
        (pk.serialize(), sk.serialize())
    }

    fn encrypt<R: Rng + CryptoRng + ?Sized>(
        to: &Self::PublicKey,
        msg: &[u8],
        _rng: &mut R,
    ) -> Vec<u8> {
        ecies::encrypt(to, msg).expect("encryption must succeed")
    }

    fn decrypt(with: &Self::SecretKey, ciph: &[u8]) -> Option<Vec<u8>> {
        ecies::decrypt(with, ciph).ok()
    }
}

#[test]
fn eciestest() {
    let mut rng = thread_rng();
    let (pk, sk) = ECIES::keygen(&mut rng);
    let c = ECIES::encrypt(&pk, &"bla".as_bytes(), &mut rng);
    assert_eq!(ECIES::decrypt(&sk, &c).unwrap(), "bla".as_bytes())
}
