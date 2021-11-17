use ark_crypto_primitives::crh::constraints::{CRHSchemeGadget, TwoToOneCRHSchemeGadget};
use ark_crypto_primitives::crh::{CRHScheme, TwoToOneCRHScheme};
use ark_crypto_primitives::merkle_tree;
use ark_ec::models::twisted_edwards_extended::GroupAffine;
use ark_ec::models::TEModelParameters;
use ark_ff::fields::{Field, PrimeField};
use ark_nonnative_field::NonNativeFieldVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_relations::r1cs::{Namespace, SynthesisError};
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

pub trait ParameterFunction {
    type Parameters;

    fn parameters() -> &'static Self::Parameters;
}

pub trait ParameterGadget<F: Field> {
    type ParametersVar;

    fn allocate(cs: impl Into<Namespace<F>>) -> Result<Self::ParametersVar, SynthesisError>;
}

pub trait CompressionFunction<T>: ParameterFunction {
    type CRHScheme: CRHScheme<Input = [T], Output = T>;
    type TwoToOneCRHScheme: TwoToOneCRHScheme<Output = T, Input = T>;

    fn compress(a: &T, b: &T) -> T;
}

pub trait CompressionFunctionGadget<T, U, H: CompressionFunction<U>, F: Field>:
    ParameterGadget<F>
{
    type CRHScheme: CRHSchemeGadget<
        H::CRHScheme,
        F,
        InputVar = [T],
        OutputVar = T,
        ParametersVar = Self::ParametersVar,
    >;
    type TwoToOneCRHScheme: TwoToOneCRHSchemeGadget<
        H::TwoToOneCRHScheme,
        F,
        OutputVar = T,
        InputVar = T,
        ParametersVar = Self::ParametersVar,
    >;

    fn compress(params: &Self::ParametersVar, a: &T, b: &T) -> Result<T, SynthesisError>;
}

pub trait CommitmentScheme<F>: ParameterFunction {
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

pub trait CommitmentSchemeGadget<T, U, H: CommitmentScheme<U>, F: Field>:
    ParameterGadget<F>
{
    fn commit(params: &Self::ParametersVar, x: (&T, &T), r: &T) -> Result<T, SynthesisError>;
}

impl<T, U, H: CompressionFunction<U>, F: Field, V> CommitmentSchemeGadget<T, U, H, F> for V
where
    V: CompressionFunctionGadget<T, U, H, F>,
{
    fn commit(params: &Self::ParametersVar, (a, b): (&T, &T), r: &T) -> Result<T, SynthesisError> {
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

pub trait HomomorphicCommitmentSchemeGadget<F: PrimeField, T, V, R>: ParameterGadget<F>
where
    V: EqGadget<F> + Add<Output = V> + Sub<Output = V>,
    R: EqGadget<F> + Add<Output = R> + Sub<Output = R>,
{
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

pub struct MultiBasePedersenGadget<P: TEModelParameters, H, HGadget>(
    pub PhantomData<(P, H, HGadget)>,
)
where
    P::BaseField: PrimeField;

#[allow(unused_variables)]
impl<
        P: TEModelParameters,
        H: CompressionFunction<P::BaseField>,
        HGadget: CompressionFunctionGadget<FpVar<P::BaseField>, P::BaseField, H, P::BaseField>,
    > ParameterGadget<P::BaseField> for MultiBasePedersenGadget<P, H, HGadget>
where
    P::BaseField: PrimeField,
{
    type ParametersVar = <HGadget as ParameterGadget<P::BaseField>>::ParametersVar;

    fn allocate(
        cs: impl Into<Namespace<P::BaseField>>,
    ) -> Result<Self::ParametersVar, SynthesisError> {
        HGadget::allocate(cs)
    }
}

#[allow(unused_variables)]
impl<
        P: TEModelParameters,
        H: CompressionFunction<P::BaseField>,
        HGadget: CompressionFunctionGadget<FpVar<P::BaseField>, P::BaseField, H, P::BaseField>,
    >
    HomomorphicCommitmentSchemeGadget<
        P::BaseField,
        FpVar<P::BaseField>,
        NonNativeFieldVar<P::ScalarField, P::BaseField>,
        NonNativeFieldVar<P::ScalarField, P::BaseField>,
    > for MultiBasePedersenGadget<P, H, HGadget>
where
    P::BaseField: PrimeField,
{
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

pub trait MerkleTreeParams<F: Field, L: CRHScheme, C: TwoToOneCRHScheme> {
    type Config: merkle_tree::Config<
        Leaf = [F],
        LeafDigest = F,
        InnerDigest = F,
        LeafHash = L,
        TwoToOneHash = C,
    >;
    type LeafParamVar: AllocVar<L::Parameters, F>;
    type CompressionParamVar: AllocVar<C::Parameters, F>;

    fn leaf_param() -> &'static L::Parameters;
    fn compression_param() -> &'static C::Parameters;
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
