use crate::primitives::*;
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::fields::{Field, PrimeField};
use ark_ff::UniformRand;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations;
use ark_relations::r1cs::{Namespace, SynthesisError};
use rand::{CryptoRng, Rng};
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::io::{self, Cursor, Read, Write};
use std::marker::PhantomData;

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

pub trait OTAGadget<OTA: OneTimeAccount, F: Field> {
    type KeyDeriveParams;
    type GenParams;
    type TagEvalParams;
    type SecretKey: AllocVar<OTA::SecretKey, F>;
    type PublicKey: AllocVar<OTA::PartialPublicKey, F>;
    type Randomness: AllocVar<OTA::Randomness, F>;
    type Attributes: AllocVar<OTA::Attributes, F>;
    type Note: AllocVar<OTA::Note, F>;
    type Nullifier: AllocVar<OTA::Nullifier, F>;

    fn derive_public_key(
        params: &Self::KeyDeriveParams,
        sk: &Self::SecretKey,
    ) -> Result<Self::PublicKey, SynthesisError>;
    fn gen(
        params: &Self::GenParams,
        pk: &Self::PublicKey,
        attribs: &Self::Attributes,
        r: &Self::Randomness,
    ) -> Result<Self::Note, SynthesisError>;
    fn nul_eval(
        params: &Self::TagEvalParams,
        sk: &Self::SecretKey,
        r: &Self::Randomness,
    ) -> Result<Self::Nullifier, SynthesisError>;
}

pub trait ZSwapParameters {
    type F: PrimeField;
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
}

pub struct Randomness<F> {
    pub rk: F,
    pub rc: F,
    pub rn: F,
}

impl<F: ToBytes> ToBytes for Randomness<F> {
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.rk.write(&mut writer)?;
        self.rc.write(&mut writer)?;
        self.rn.write(&mut writer)
    }
}

impl<F: FromBytes> FromBytes for Randomness<F> {
    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        Ok(Randomness {
            rk: F::read(&mut reader)?,
            rc: F::read(&mut reader)?,
            rn: F::read(&mut reader)?,
        })
    }
}

impl<F: UniformRand> UniformRand for Randomness<F> {
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Randomness {
            rk: F::rand(rng),
            rc: F::rand(rng),
            rn: F::rand(rng),
        }
    }
}

pub struct Attributes {
    pub value: u64,
    pub type_: u64,
}

impl Attributes {
    fn as_field<F: Field>(&self) -> F {
        ((self.value as u128) << 64 | (self.type_ as u128)).into()
    }
}

impl ToBytes for Attributes {
    fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.value.write(&mut writer)?;
        self.type_.write(&mut writer)
    }
}

impl FromBytes for Attributes {
    fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        Ok(Attributes {
            value: u64::read(&mut reader)?,
            type_: u64::read(&mut reader)?,
        })
    }
}

impl<P: ZSwapParameters> OneTimeAccount for ZSwapOTA<P> {
    type SecretKey = (P::F, <P::Encrypt as EncryptionScheme>::SecretKey);
    type PublicKey = (P::F, <P::Encrypt as EncryptionScheme>::PublicKey);
    type PartialPublicKey = P::F;
    type Randomness = Randomness<P::F>;
    /// (color, value), where color is rejection-sampled preimage of the corresponding base.
    type Attributes = Attributes;
    type Note = P::F;
    type Ciphertext = Vec<u8>;
    type Nullifier = P::F;

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

    fn gen(
        a_pk: &Self::PartialPublicKey,
        attribs: &Self::Attributes,
        r: &Self::Randomness,
    ) -> Self::Note {
        let c1 = P::Commit::commit((a_pk, &r.rn), &r.rk);
        P::Commit::commit((&c1, &attribs.as_field()), &r.rc)
    }

    fn enc<R: Rng + CryptoRng + ?Sized>(
        (_, pk_enc): &Self::PublicKey,
        attribs: &Self::Attributes,
        r: &Self::Randomness,
        rng: &mut R,
    ) -> Self::Ciphertext {
        let mut message = Vec::new();
        r.write(&mut message)
            .and_then(|_| attribs.write(&mut message))
            .expect("Write to Vec should succeed");
        P::Encrypt::encrypt(pk_enc, &message, rng)
    }

    fn receive(
        note: &Self::Note,
        ciphertext: &Self::Ciphertext,
        sk: &Self::SecretKey,
    ) -> Option<(Self::Attributes, Self::Randomness)> {
        let mut plaintext = Cursor::new(P::Encrypt::decrypt(&sk.1, ciphertext)?);
        let r = Self::Randomness::read(&mut plaintext).ok()?;
        let a = Attributes::read(&mut plaintext).ok()?;
        // Verify comm
        let a_pk = Self::derive_public_key(sk);
        let c1 = P::Commit::commit((&a_pk, &r.rn), &r.rk);
        let c2 = P::Commit::commit((&c1, &a.as_field()), &r.rc);
        if &c2 != note {
            None
        } else {
            Some((a, r))
        }
    }

    fn nul_eval((a_sk, _): &Self::SecretKey, r: &Self::Randomness) -> Self::Nullifier {
        let c1 = P::Hash::compress(a_sk, &r.rn);
        P::Hash::compress(&Self::DOMAIN_SEP_INVALIDATOR.into(), &c1)
    }
}

pub trait ZSwapGadgetParameters {
    type F: PrimeField;
    type Hash: CompressionFunctionGadget<FpVar<Self::F>>;
    type Commit: CommitmentSchemeGadget<FpVar<Self::F>>;
}

pub struct ZSwapOTAGadget<P>(PhantomData<P>);

pub struct SecretKeyVar<F: PrimeField>(FpVar<F>);

impl<F: PrimeField, T> AllocVar<(F, T), F> for SecretKeyVar<F> {
    fn new_variable<U: Borrow<(F, T)>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<U, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(SecretKeyVar(FpVar::<F>::new_variable(
            cs,
            || f().map(|sk| sk.borrow().0),
            mode,
        )?))
    }
}

pub struct RandomnessVar<F: PrimeField> {
    pub rk: FpVar<F>,
    pub rc: FpVar<F>,
    pub rn: FpVar<F>,
}
impl<F: PrimeField> AllocVar<Randomness<F>, F> for RandomnessVar<F> {
    fn new_variable<U: Borrow<Randomness<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<U, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        f().and_then(|r| {
            Ok(RandomnessVar {
                rk: FpVar::<F>::new_variable(
                    ark_relations::ns!(cs, "rk"),
                    || Ok(r.borrow().rk),
                    mode,
                )?,
                rc: FpVar::<F>::new_variable(
                    ark_relations::ns!(cs, "rc"),
                    || Ok(r.borrow().rc),
                    mode,
                )?,
                rn: FpVar::<F>::new_variable(
                    ark_relations::ns!(cs, "rn"),
                    || Ok(r.borrow().rn),
                    mode,
                )?,
            })
        })
    }
}

pub struct AttributesVar<F: PrimeField> {
    pub value: FpVar<F>,
    pub type_: FpVar<F>,
}

impl<F: PrimeField> AttributesVar<F> {
    fn as_field(&self) -> Result<FpVar<F>, SynthesisError> {
        let two_pow_64 = FpVar::<F>::Constant((u64::MAX as u128 + 1).into());
        Ok(self.value.clone() * two_pow_64 + self.type_.clone())
    }
}

impl<F: PrimeField> AllocVar<Attributes, F> for AttributesVar<F> {
    fn new_variable<U: Borrow<Attributes>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<U, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        f().and_then(|a| {
            let two_pow_64 = FpVar::<F>::Constant((u64::MAX as u128 + 1).into());
            let value = FpVar::<F>::new_variable(
                ark_relations::ns!(cs, "value"),
                || Ok(F::from(a.borrow().value)),
                mode,
            )?;
            value.enforce_cmp(&two_pow_64, Ordering::Less, false)?;
            let type_ = FpVar::<F>::new_variable(
                ark_relations::ns!(cs, "type"),
                || Ok(F::from(a.borrow().type_)),
                mode,
            )?;
            type_.enforce_cmp(&two_pow_64, Ordering::Less, false)?;
            Ok(AttributesVar { value, type_ })
        })
    }
}

impl<P: ZSwapGadgetParameters, P1: ZSwapParameters<F = P::F>> OTAGadget<ZSwapOTA<P1>, P::F>
    for ZSwapOTAGadget<P>
{
    type KeyDeriveParams = <P::Hash as CompressionFunctionGadget<FpVar<P::F>>>::ParametersVar;
    type GenParams = <P::Commit as CommitmentSchemeGadget<FpVar<P::F>>>::ParametersVar;
    type TagEvalParams = <P::Hash as CompressionFunctionGadget<FpVar<P::F>>>::ParametersVar;
    type SecretKey = SecretKeyVar<P::F>;
    type PublicKey = FpVar<P::F>;
    type Randomness = RandomnessVar<P::F>;
    type Attributes = AttributesVar<P::F>;
    type Note = FpVar<P::F>;
    type Nullifier = FpVar<P::F>;

    fn derive_public_key(
        hash_params: &Self::KeyDeriveParams,
        sk: &Self::SecretKey,
    ) -> Result<Self::PublicKey, SynthesisError> {
        let domain_sep_var = FpVar::Constant(ZSwapOTA::<P1>::DOMAIN_SEP_PK_DERIV.into());
        P::Hash::compress(hash_params, &domain_sep_var, &sk.0)
    }

    fn gen(
        params: &Self::GenParams,
        pk: &Self::PublicKey,
        attribs: &Self::Attributes,
        r: &Self::Randomness,
    ) -> Result<Self::Note, SynthesisError> {
        let c1 = P::Commit::commit(params, (pk, &r.rn), &r.rk)?;
        P::Commit::commit(params, (&c1, &attribs.as_field()?), &r.rc)
    }

    fn nul_eval(
        params: &Self::TagEvalParams,
        sk: &Self::SecretKey,
        r: &Self::Randomness,
    ) -> Result<Self::Nullifier, SynthesisError> {
        let c1 = P::Hash::compress(params, &sk.0, &r.rn)?;
        let domain_sep_invalidator = FpVar::Constant(ZSwapOTA::<P1>::DOMAIN_SEP_INVALIDATOR.into());
        P::Hash::compress(params, &domain_sep_invalidator, &c1)
    }
}

pub struct DefaultParameters;

impl ZSwapParameters for DefaultParameters {
    type F = ::ark_bls12_381::Fq;
    type Hash = crate::poseidon::Poseidon;
    type Commit = crate::poseidon::Poseidon;
    type Encrypt = crate::primitives::ECIES;
}

impl ZSwapGadgetParameters for DefaultParameters {
    type F = ::ark_bls12_381::Fq;
    type Hash = crate::poseidon::Poseidon;
    type Commit = crate::poseidon::Poseidon;
}
