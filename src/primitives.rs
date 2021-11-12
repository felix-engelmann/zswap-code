use ark_relations::r1cs::SynthesisError;
use rand::{CryptoRng, Rng};

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
    // FIXME: What do we need for homomorphism? Addition and subtraction constraints on commitment
    // and randomness types?
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
