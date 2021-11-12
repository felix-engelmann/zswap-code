use ark_relations::r1cs::SynthesisError;
#[cfg(test)]
use rand::thread_rng;
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
