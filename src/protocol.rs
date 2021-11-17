#![allow(unused_variables, dead_code)]
use crate::ota::{OTAGadget, OneTimeAccount};
use crate::primitives::*;
use crate::sparse_merkle_tree::SparseMerkleTree;
use crate::zswap::{Transaction, ZSwapScheme};
use ark_crypto_primitives::merkle_tree::constraints::PathVar;
use ark_crypto_primitives::merkle_tree::{self, IdentityDigestConverter, Path};
use ark_ec::models::twisted_edwards_extended::GroupAffine;
use ark_ec::models::{ModelParameters, TEModelParameters};
use ark_ff::bytes::{FromBytes, ToBytes};
use ark_ff::fields::{Field, PrimeField};
use ark_ff::{UniformRand, Zero};
use ark_nonnative_field::NonNativeFieldVar;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_relations::r1cs::{
    self, ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError,
};
use ark_relations::{self, ns};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use rand::{CryptoRng, Rng};
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::hash::Hash;
use std::io::{self, Cursor, Read, Write};
use std::marker::PhantomData;

#[allow(type_alias_bounds)]
pub type EmbeddedField<P: ZSwapParameters> = <P::G as ModelParameters>::ScalarField;
#[allow(type_alias_bounds)]
pub type MerkleTreeConfig<P: ZSwapParameters> = <P::MerkleTree as MerkleTreeParams<
    P::F,
    <P::Hash as CompressionFunction<P::F>>::CRHScheme,
    <P::Hash as CompressionFunction<P::F>>::TwoToOneCRHScheme,
>>::Config;

pub trait ZSwapParameters {
    type F: PrimeField;
    type G: TEModelParameters<BaseField = Self::F>;
    type Hash: CompressionFunction<Self::F>
        + CommitmentScheme<Self::F>
        + ParameterFunction<Parameters = Self::CryptoParameters>;

    type HashGadget: CompressionFunctionGadget<FpVar<Self::F>, Self::F, Self::Hash, Self::F>
        + CommitmentSchemeGadget<FpVar<Self::F>, Self::F, Self::Hash, Self::F>
        + ParameterGadget<Self::F, ParametersVar = Self::CryptoParametersVar>;
    type Encrypt: EncryptionScheme;
    type CryptoParameters;
    type CryptoParametersVar: AllocVar<Self::CryptoParameters, Self::F>;
    type MerkleTree: MerkleTreeParams<
        Self::F,
        <Self::Hash as CompressionFunction<Self::F>>::CRHScheme,
        <Self::Hash as CompressionFunction<Self::F>>::TwoToOneCRHScheme,
        LeafParamVar = Self::CryptoParametersVar,
        CompressionParamVar = Self::CryptoParametersVar,
    >;
    //type MerkleTreeGadget: merkle_tree::constraints::ConfigGadget<MerkleTreeConfig<Self>, Self::F, Leaf=[FpVar<Self::F>], LeafDigest=FpVar<Self::F>, InnerDigest=FpVar<Self::F>>;
    type HomomorphicCommitment: HomomorphicCommitmentScheme<
        Self::F,
        EmbeddedField<Self>,
        EmbeddedField<Self>,
    >;
    type SNARK: CircuitSpecificSetupSNARK<Self::F>;
}

struct MerkleTreeConfigGadget<P>(PhantomData<P>);

impl<P: ZSwapParameters> merkle_tree::constraints::ConfigGadget<MerkleTreeConfig<P>, P::F>
    for MerkleTreeConfigGadget<P>
{
    type Leaf = [FpVar<P::F>];
    type LeafDigest = FpVar<P::F>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<P::F>>;
    type InnerDigest = FpVar<P::F>;
    type LeafHash =
        <P::HashGadget as CompressionFunctionGadget<FpVar<P::F>, P::F, P::Hash, P::F>>::CRHScheme;
    type TwoToOneHash = <P::HashGadget as CompressionFunctionGadget<
        FpVar<P::F>,
        P::F,
        P::Hash,
        P::F,
    >>::TwoToOneCRHScheme;
}

pub struct DefaultParameters;

impl ZSwapParameters for DefaultParameters {
    type F = ::ark_bls12_381::Fr;
    type G = ::ark_ed_on_bls12_381::EdwardsParameters;
    type Hash = crate::poseidon::Poseidon;
    type HashGadget = crate::poseidon::Poseidon;
    type Encrypt = crate::primitives::ECIES;
    type CryptoParameters = ::ark_sponge::poseidon::PoseidonParameters<Self::F>;
    type CryptoParametersVar =
        ::ark_crypto_primitives::crh::poseidon::constraints::CRHParametersVar<Self::F>;
    type MerkleTree = crate::poseidon::Poseidon;
    type HomomorphicCommitment =
        crate::primitives::MultiBasePedersen<Self::G, crate::poseidon::Poseidon>;
    type SNARK =
        ::ark_groth16::Groth16<::ark_ec::models::bls12::Bls12<::ark_bls12_381::Parameters>>;
}

pub struct ZSwap<P>(PhantomData<P>);

impl<P: ZSwapParameters> ZSwap<P> {
    /// Randomly sampled general domain separator for this protocol
    const DOMAIN_SEP: u64 = 1_497_537_315 << 32;
    const DOMAIN_SEP_PK_DERIV: u64 = Self::DOMAIN_SEP | 1;
    const DOMAIN_SEP_INVALIDATOR: u64 = Self::DOMAIN_SEP | 2;
}

#[derive(Default)]
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

impl<P: ZSwapParameters> OneTimeAccount for ZSwap<P> {
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
        let c1 = P::Hash::commit((a_pk, &r.rn), &r.rk);
        P::Hash::commit((&c1, &attribs.as_field()), &r.rc)
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
        let c1 = P::Hash::commit((&a_pk, &r.rn), &r.rk);
        let c2 = P::Hash::commit((&c1, &a.as_field()), &r.rc);
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

impl<P: ZSwapParameters> OTAGadget<P::F> for ZSwap<P> {
    type KeyDeriveParams = <P::HashGadget as ParameterGadget<P::F>>::ParametersVar;
    type GenParams = <P::HashGadget as ParameterGadget<P::F>>::ParametersVar;
    type TagEvalParams = <P::HashGadget as ParameterGadget<P::F>>::ParametersVar;
    type SecretKeyVar = SecretKeyVar<P::F>;
    type PublicKeyVar = FpVar<P::F>;
    type RandomnessVar = RandomnessVar<P::F>;
    type AttributesVar = AttributesVar<P::F>;
    type NoteVar = FpVar<P::F>;
    type NullifierVar = FpVar<P::F>;

    fn derive_public_key_gadget(
        hash_params: &Self::KeyDeriveParams,
        sk: &Self::SecretKeyVar,
    ) -> Result<Self::PublicKeyVar, SynthesisError> {
        let domain_sep_var = FpVar::Constant(Self::DOMAIN_SEP_PK_DERIV.into());
        P::HashGadget::compress(hash_params, &domain_sep_var, &sk.0)
    }

    fn gen_gadget(
        params: &Self::GenParams,
        pk: &Self::PublicKeyVar,
        attribs: &Self::AttributesVar,
        r: &Self::RandomnessVar,
    ) -> Result<Self::NoteVar, SynthesisError> {
        let c1 = P::HashGadget::commit(params, (pk, &r.rn), &r.rk)?;
        P::HashGadget::commit(params, (&c1, &attribs.as_field()?), &r.rc)
    }

    fn nul_eval_gadget(
        params: &Self::TagEvalParams,
        sk: &Self::SecretKeyVar,
        r: &Self::RandomnessVar,
    ) -> Result<Self::NullifierVar, SynthesisError> {
        let c1 = P::HashGadget::compress(params, &sk.0, &r.rn)?;
        let domain_sep_invalidator = FpVar::Constant(Self::DOMAIN_SEP_INVALIDATOR.into());
        P::HashGadget::compress(params, &domain_sep_invalidator, &c1)
    }
}

const MERKLE_TREE_HEIGHT: usize = 32;

pub struct ZSwapState<P: ZSwapParameters> {
    notes: HashSet<<ZSwap<P> as OneTimeAccount>::Note>,
    nullifiers: HashSet<<ZSwap<P> as OneTimeAccount>::Nullifier>,
    merkle_tree: SparseMerkleTree<MerkleTreeConfig<P>>,
    merkle_tree_next_index: usize,
    pub roots: Vec<P::F>,
}

impl<P: ZSwapParameters + 'static> ZSwapState<P> {
    pub fn new() -> Self {
        let merkle_tree = SparseMerkleTree::blank(
            P::MerkleTree::leaf_param(),
            P::MerkleTree::compression_param(),
            MERKLE_TREE_HEIGHT,
        );
        ZSwapState {
            notes: HashSet::new(),
            nullifiers: HashSet::new(),
            roots: vec![merkle_tree.root()],
            merkle_tree,
            merkle_tree_next_index: 0,
        }
    }
}

pub struct ZSwapPublicParams<P: ZSwapParameters> {
    spend_proving_key: <P::SNARK as SNARK<P::F>>::ProvingKey,
    spend_verifying_key: <P::SNARK as SNARK<P::F>>::VerifyingKey,
    output_proving_key: <P::SNARK as SNARK<P::F>>::ProvingKey,
    output_verifying_key: <P::SNARK as SNARK<P::F>>::VerifyingKey,
}

struct LangSpend<P: ZSwapParameters> {
    // Public inputs
    st: P::F,
    nul: P::F,
    com: GroupAffine<P::G>,

    // Witnesses
    path: Path<MerkleTreeConfig<P>>,
    sk: P::F,
    type_: P::F,
    value: P::F,
    r: <ZSwap<P> as OneTimeAccount>::Randomness,
    rc: EmbeddedField<P>,
}

impl<P: ZSwapParameters> LangSpend<P> {
    // We need a blank circuit for constraint generation
    fn new() -> Self {
        LangSpend {
            st: Default::default(),
            nul: Default::default(),
            com: Default::default(),

            path: Path {
                leaf_sibling_hash: Default::default(),
                auth_path: vec![Default::default(); MERKLE_TREE_HEIGHT - 2],
                leaf_index: Default::default(),
            },
            sk: Default::default(),
            type_: Default::default(),
            value: Default::default(),
            r: Default::default(),
            rc: Default::default(),
        }
    }
}

impl<P: ZSwapParameters> ConstraintSynthesizer<P::F> for LangSpend<P> {
    fn generate_constraints(self, cs: ConstraintSystemRef<P::F>) -> r1cs::Result<()> {
        let st = FpVar::new_input(ns!(cs, "st"), || Ok(self.st))?;
        let nul = FpVar::new_input(ns!(cs, "nul"), || Ok(self.nul))?;
        let com = AffineVar::<_, FpVar<P::F>>::new_input(ns!(cs, "com"), || Ok(self.com))?;

        let path =
            PathVar::<_, P::F, MerkleTreeConfigGadget<P>>::new_witness(ns!(cs, "path"), || {
                Ok(self.path)
            })?;
        let sk = SecretKeyVar(FpVar::new_witness(ns!(cs, "sk"), || Ok(self.sk))?);
        let type_ = FpVar::new_witness(ns!(cs, "type"), || Ok(self.type_))?;
        let value = FpVar::new_witness(ns!(cs, "value"), || Ok(self.value))?;
        let r = RandomnessVar::new_witness(ns!(cs, "r"), || Ok(self.r))?;
        let rc = NonNativeFieldVar::new_witness(ns!(cs, "rc"), || Ok(self.rc))?;

        let params = P::HashGadget::allocate(ns!(cs, "poseidon-parameters"))?;
        let pk = ZSwap::<P>::derive_public_key_gadget(&params, &sk)?;
        let attribs = AttributesVar { type_, value };
        let note = ZSwap::<P>::gen_gadget(&params, &pk, &attribs, &r)?;

        let root2 = path.calculate_root(&params, &params, &[note][..])?;
        st.enforce_equal(&root2)?;

        unimplemented!()
    }
}

struct LangOutput<P: ZSwapParameters>(PhantomData<P>);

impl<P: ZSwapParameters> LangOutput<P> {
    fn new() -> Self {
        unimplemented!()
    }
}

impl<P: ZSwapParameters> ConstraintSynthesizer<P::F> for LangOutput<P> {
    fn generate_constraints(self, cs: ConstraintSystemRef<P::F>) -> r1cs::Result<()> {
        unimplemented!()
    }
}

#[allow(type_alias_bounds)]
type Proof<P: ZSwapParameters> = <P::SNARK as SNARK<P::F>>::Proof;
#[allow(type_alias_bounds)]
type HomomorphicCommitment<P: ZSwapParameters> =
    <P::HomomorphicCommitment as HomomorphicCommitmentScheme<
        P::F,
        EmbeddedField<P>,
        EmbeddedField<P>,
    >>::Commitment;

pub struct ZSwapSignature<P: ZSwapParameters> {
    pub input_signatures: HashSet<(
        Proof<P>,
        HomomorphicCommitment<P>,
        <ZSwap<P> as OneTimeAccount>::Nullifier,
    )>,
    pub output_signatures: HashSet<(
        Proof<P>,
        HomomorphicCommitment<P>,
        (
            <ZSwap<P> as OneTimeAccount>::Note,
            <ZSwap<P> as OneTimeAccount>::Ciphertext,
        ),
    )>,
    pub randomness: EmbeddedField<P>,
}

impl<P: ZSwapParameters> ZSwapScheme for ZSwap<P>
where
    EmbeddedField<P>: Hash,
    HomomorphicCommitment<P>: Hash + Clone,
    Proof<P>: Eq + Hash,
{
    type PublicParameters = ZSwapPublicParams<P>;
    type Signature = ZSwapSignature<P>;
    type State = ZSwapState<P>;
    type StateWitness = Path<MerkleTreeConfig<P>>;
    type Error = <P::SNARK as SNARK<P::F>>::Error;

    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self::PublicParameters, Self::Error> {
        let (spend_proving_key, spend_verifying_key) = P::SNARK::setup(LangSpend::<P>::new(), rng)?;
        let (output_proving_key, output_verifying_key) =
            P::SNARK::setup(LangOutput::<P>::new(), rng)?;
        Ok(ZSwapPublicParams {
            spend_proving_key,
            spend_verifying_key,
            output_proving_key,
            output_verifying_key,
        })
    }

    fn sign_tx<R: Rng + CryptoRng + ?Sized>(
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
    ) -> Result<Self::Signature, Self::Error> {

        let rc_s: Vec<EmbeddedField<P>> =
            (0..inputs.len()).map(|_| UniformRand::rand(rng)).collect();
        let com_s: Vec<_> =
            inputs.iter().zip(rc_s.iter())
            .map(|(input,rc)|
              <MultiBasePedersen<P::G,P::Hash> as
               HomomorphicCommitmentScheme<_,_,_>>::
                 commit(&From::from(input.4.type_),
                        &From::from(input.4.value),
                        &rc))
            .collect();

        let rc_t: Vec<EmbeddedField<P>> =
            (0..inputs.len()).map(|_| UniformRand::rand(rng)).collect();
        let com_t: Vec<_> =
            outputs.iter().zip(rc_t.iter())
            .map(|(output,rc)|
              <MultiBasePedersen<P::G,P::Hash> as
               HomomorphicCommitmentScheme<_,_,_>>::
                 commit(&From::from(output.2.type_),
                        &From::from(output.2.value),
                        &rc))
            .collect();

        unimplemented!()
    }

    fn verify_tx<R: Rng + CryptoRng + ?Sized>(
        params: &Self::PublicParameters,
        state: &Self::State,
        transaction: &Transaction<Self>,
        signature: &Self::Signature,
        rng: &mut R,
    ) -> Result<bool, Self::Error> {
        unimplemented!()
    }

    fn apply_input(state: &mut Self::State, input: &Self::Nullifier) {
        state.nullifiers.insert(*input);
    }

    fn apply_output(state: &mut Self::State, output: &Self::Note) {
        state.notes.insert(*output);
        state
            .merkle_tree
            .update(state.merkle_tree_next_index, &[*output][..])
            .expect("insertion must succeed");
        state.roots.push(state.merkle_tree.root())
    }

    fn merge<R: Rng + CryptoRng + ?Sized>(
        params: &Self::PublicParameters,
        signatures: &[Self::Signature],
        rng: &mut R,
    ) -> Result<Self::Signature, Self::Error> {
        let mut input_signatures = HashSet::new();
        let mut output_signatures = HashSet::new();
        let mut randomness = EmbeddedField::<P>::zero();
        for sig in signatures {
            input_signatures.extend(sig.input_signatures.iter().cloned());
            output_signatures.extend(sig.output_signatures.iter().cloned());
            randomness += sig.randomness;
        }
        Ok(ZSwapSignature {
            input_signatures,
            output_signatures,
            randomness,
        })
    }
}
