use rand::{Rng, CryptoRng};
use ark_ff::UniformRand;
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::fields::Field;
use ark_r1cs_std::alloc::AllocVar;
use ark_relations::r1cs::SynthesisError;
use std::marker::PhantomData;
use std::io::Cursor;

pub trait OneTimeAccount {
    type SecretKey;
    type PublicKey;
    type PartialPublicKey;
    type Randomness;
    type Attributes;
    type Account;
    type Invalidator;

    fn keygen<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey);
    fn derive_public_key(sk: &Self::SecretKey) -> Self::PartialPublicKey;
    fn ot_gen<R: Rng + CryptoRng + ?Sized>(pk: &Self::PublicKey, attribs: &Self::Attributes, r: &Self::Randomness, rng: &mut R) -> Self::Account;
    fn recieve(acc: &Self::Account, sk: &Self::SecretKey) -> Option<(Self::Attributes, Self::Randomness)>;
    fn tag_eval(sk: &Self::SecretKey, r: &Self::Randomness) -> Self::Invalidator;
}

pub trait OTAConstraints<OTA: OneTimeAccount, F: Field> {
    type SecretKey: AllocVar<OTA::SecretKey, F>;
    type PublicKey: AllocVar<OTA::PublicKey, F>;
    type Randomness: AllocVar<OTA::Randomness, F>;
    type Attributes: AllocVar<OTA::Attributes, F>;
    type Account: AllocVar<OTA::Account, F>;
    type Invalidator: AllocVar<OTA::Invalidator, F>;

    fn derive_public_key(sk: &Self::SecretKey) -> Result<Self::PublicKey, SynthesisError>;
    fn ot_gen(acc: &Self::Account, attribs: &Self::Attributes, r: &Self::Randomness) -> Result<Self::Account, SynthesisError>;
    fn tag_eval(sk: &Self::SecretKey, r: &Self::Randomness) -> Result<Self::Invalidator, SynthesisError>;
}

pub trait EncryptionScheme {
    type SecretKey;
    type PublicKey;

    fn keygen<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey);
    fn encrypt<R: Rng + CryptoRng + ?Sized>(to: &Self::PublicKey, msg: &[u8], rng: &mut R) -> Vec<u8>;
    fn decrypt(with: &Self::SecretKey, ciph: &[u8]) -> Option<Vec<u8>>;
}

pub trait CompressionFunction<F> {
    fn compress(a: &F, b: &F) -> F;
}

pub trait CommitmentScheme<F> {
    // It seems this is the structure all of our commitments follow?
    fn commit(x: (&F, &F), r: &F) -> F;
    // FIXME: What do we need for homomorphism? Addition and subtraction constraints on commitment
    // and randomness types?
}

pub trait ZSwapParameters {
    type F: Field;
    type Hash: CompressionFunction<Self::F>;
    type Commit: CommitmentScheme<Self::F>;
    type Encrypt: EncryptionScheme;
}

pub struct ZSwapOTA<P>(PhantomData<P>);

impl<P: ZSwapParameters> ZSwapOTA<P> {
    /// Randomly sampled general domain separator for this protocol
    const DOMAIN_SEP: u64 = 1_497_537_315 << 32;
    const DOMAIN_SEP_PK_DERIV: u64 = Self::DOMAIN_SEP | 1;
    const DOMAIN_SEP_INVALIDATOR: u64 = Self::DOMAIN_SEP | 2;

    fn attribs_as_field((a, b): &<Self as OneTimeAccount>::Attributes) -> P::F {
        ((*a as u128) << 64 | (*b as u128)).into()
    }
}

impl<P: ZSwapParameters> OneTimeAccount for ZSwapOTA<P> {
    type SecretKey = (P::F, <P::Encrypt as EncryptionScheme>::SecretKey);
    type PublicKey = (P::F, <P::Encrypt as EncryptionScheme>::PublicKey);
    type PartialPublicKey = P::F;
    type Randomness = (P::F, P::F, P::F);
    /// (color, value), where color is rejection-sampled preimage of the corresponding base.
    type Attributes = (u64, u64);
    type Account = (P::F, Vec<u8>);
    type Invalidator = P::F;

    fn keygen<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        let a_sk = P::F::rand(rng);
        let (pk_enc, sk_enc) = P::Encrypt::keygen(rng);
        let sk = (a_sk, sk_enc);
        let a_pk = Self::derive_public_key(&sk);
        let pk = (a_pk, pk_enc);
        (pk, sk)
    }

    fn derive_public_key(sk: &Self::SecretKey) -> Self::PartialPublicKey {
        P::Hash::compress(&Self::DOMAIN_SEP_PK_DERIV.into(), &sk.0)
    }

    fn ot_gen<R: Rng + CryptoRng + ?Sized>((a_pk, pk_enc): &Self::PublicKey, attribs: &Self::Attributes, (rk, rc, rn): &Self::Randomness, rng: &mut R) -> Self::Account {
        let c1 = P::Commit::commit((a_pk, &rn), rk);
        let c2 = P::Commit::commit((&c1, &Self::attribs_as_field(attribs)), rc);
        let mut message = Vec::new();
        rk.write(&mut message)
            .and_then(|_| rc.write(&mut message))
            .and_then(|_| rn.write(&mut message))
            .and_then(|_| attribs.0.write(&mut message))
            .and_then(|_| attribs.1.write(&mut message))
            .expect("Write to Vec should succeed");
        let ciphertext = P::Encrypt::encrypt(pk_enc, &message, rng);
        (c2, ciphertext)
    }

    fn recieve((comm, ciphertext): &Self::Account, sk: &Self::SecretKey) -> Option<(Self::Attributes, Self::Randomness)> {
        let mut plaintext = Cursor::new(P::Encrypt::decrypt(&sk.1, ciphertext)?);
        let rk = P::F::read(&mut plaintext).ok()?;
        let rc = P::F::read(&mut plaintext).ok()?;
        let rn = P::F::read(&mut plaintext).ok()?;
        let a1 = u64::read(&mut plaintext).ok()?;
        let a2 = u64::read(&mut plaintext).ok()?;
        // Verify comm
        let a_pk = Self::derive_public_key(sk);
        let c1 = P::Commit::commit((&a_pk, &rn), &rk);
        let c2 = P::Commit::commit((&c1, &Self::attribs_as_field(&(a1, a2))), &rc);
        if &c2 != comm {
            None
        } else {
            Some(((a1, a2), (rk, rc, rn)))
        }
    }

    fn tag_eval((a_sk, _): &Self::SecretKey, (_, _, rn): &Self::Randomness) -> Self::Invalidator {
        let c1 = P::Hash::compress(a_sk, rn);
        P::Hash::compress(&Self::DOMAIN_SEP_INVALIDATOR.into(), &c1)
    }
}
