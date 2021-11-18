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
use ark_ff::fields::PrimeField;
use ark_ff::{UniformRand, Zero};
use ark_nonnative_field::{NonNativeFieldVar, AllocatedNonNativeFieldVar, params::OptimizationType};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_relations::r1cs::{
    self, ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError, OptimizationGoal
};
use ark_relations::{self, ns};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use rand::{CryptoRng, Rng};
use std::borrow::Borrow;
use std::collections::HashSet;
use std::hash::Hash;
use std::io::{self, Cursor, Read, Write};
use std::marker::PhantomData;



////////////////////////////////////////////////////////////////////////////////
// Type aliases
////////////////////////////////////////////////////////////////////////////////


// Dp stands for "Default parameters", but this prefix could be renamed.
type DpF = ::ark_bls12_381::Fr;
type DpG = ::ark_ed_on_bls12_381::EdwardsParameters;
type DpHash = crate::poseidon::Poseidon;
type DpHashGadget = crate::poseidon::Poseidon;
type DpEncrypt = crate::primitives::ECIES;
type DpCryptoParameters = ::ark_sponge::poseidon::PoseidonParameters<DpF>;
type DpCryptoParametersVar =
    ::ark_crypto_primitives::crh::poseidon::constraints::CRHParametersVar<DpF>;
type DpMerkleTree = crate::poseidon::Poseidon;
type DpHomComScheme =
    crate::primitives::MultiBasePedersen<DpG, crate::poseidon::Poseidon>;
type DpSNARK =
    ::ark_groth16::Groth16<::ark_ec::models::bls12::Bls12<::ark_bls12_381::Parameters>>;



pub type EmbeddedField = <DpG as ModelParameters>::ScalarField;
pub type MerkleTreeConfig =
    <DpMerkleTree as MerkleTreeParams<
            DpF,
            <DpHash as CompressionFunction<DpF>>::CRHScheme,
            <DpHash as CompressionFunction<DpF>>::TwoToOneCRHScheme>>::Config;
type DpHomCom =
    <DpHomComScheme as
     HomComScheme<DpF,EmbeddedField,EmbeddedField>>::Com;
type Proof = <DpSNARK as SNARK<DpF>>::Proof;
type HomCom = <DpHomComScheme as
               HomComScheme<DpF,EmbeddedField,EmbeddedField,>>::Com;



////////////////////////////////////////////////////////////////////////////////
// Merkle Tree
////////////////////////////////////////////////////////////////////////////////


struct MerkleTreeConfigGadget();

// @volhovm: where to put these?
const OPTIMIZATION_GOAL: OptimizationGoal = OptimizationGoal::Constraints;
const OPTIMIZATION_TYPE: OptimizationType = OptimizationType::Constraints;

impl merkle_tree::constraints::ConfigGadget<MerkleTreeConfig, DpF>
    for MerkleTreeConfigGadget
{
    type Leaf = [FpVar<DpF>];
    type LeafDigest = FpVar<DpF>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<DpF>>;
    type InnerDigest = FpVar<DpF>;
    type LeafHash =
        <DpHashGadget as CompressionFunctionGadget<FpVar<DpF>, DpF, DpHash, DpF>>::CRHScheme;
    type TwoToOneHash = <DpHashGadget as CompressionFunctionGadget<
        FpVar<DpF>,
        DpF,
        DpHash,
        DpF,
    >>::TwoToOneCRHScheme;
}


////////////////////////////////////////////////////////////////////////////////
// ZSwap
////////////////////////////////////////////////////////////////////////////////


pub struct ZSwap();

impl ZSwap {
    /// Randomly sampled general domain separator for this protocol
    const DOMAIN_SEP: u64 = 1_497_537_315 << 32;
    const DOMAIN_SEP_PK_DERIV: u64 = Self::DOMAIN_SEP | 1;
    const DOMAIN_SEP_INVALIDATOR: u64 = Self::DOMAIN_SEP | 2;
}


////////////////////////////////////////////////////////////////////////////////
// Randomness
////////////////////////////////////////////////////////////////////////////////


#[derive(Default,Clone)]
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

////////////////////////////////////////////////////////////////////////////////
// Attributes
////////////////////////////////////////////////////////////////////////////////


pub struct Attributes {
    pub value: u64,
    pub type_: u64,
}

impl Attributes {
    fn as_field(&self) -> DpF {
        let value = {
            let embedded: EmbeddedField = self.value.into();
            let mut parts = AllocatedNonNativeFieldVar::get_limbs_representations(&embedded, OPTIMIZATION_TYPE)
                .expect("Getting representation of embedded field should succeed");
            while parts.len() > 1 {
                let (a, b) = (parts.pop().unwrap(), parts.pop().unwrap());
                parts.push(<DpHash as CompressionFunction<_>>::compress(&a, &b));
            }
            parts[0]
        };
        <DpHash as CompressionFunction<_>>::compress(&value, &self.type_.into())
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

impl OneTimeAccount for ZSwap {
    // @volhovm: I assume the first element is the "nullifier" sk, and the second one
    // is used for asymmetric encryption?
    type SecretKey = (DpF, <DpEncrypt as EncryptionScheme>::SecretKey);
    type PublicKey = (DpF, <DpEncrypt as EncryptionScheme>::PublicKey);
    type PartialPublicKey = DpF;
    type Randomness = Randomness<DpF>;
    /// (color, value), where color is rejection-sampled preimage of the corresponding base.
    type Attributes = Attributes;
    type Note = DpF;
    type Ciphertext = Vec<u8>;
    type Nullifier = DpF;

    fn keygen<R: Rng + CryptoRng + ?Sized>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        let a_sk = DpF::rand(rng);
        let (pk_enc, sk_enc) = DpEncrypt::keygen(rng);
        let sk = (a_sk, sk_enc);
        let a_pk = Self::derive_public_key(&sk);
        let pk = (a_pk, pk_enc);
        (pk, sk)
    }

    fn derive_public_key(sk: &Self::SecretKey) -> Self::PartialPublicKey {
        <DpHash as CompressionFunction<_>>::compress(&Self::DOMAIN_SEP_PK_DERIV.into(), &sk.0)
    }

    fn gen(
        a_pk: &Self::PartialPublicKey,
        attribs: &Self::Attributes,
        r: &Self::Randomness,
    ) -> Self::Note {
        let c1 = <DpHash as ComScheme<_>>::commit((a_pk, &r.rn), &r.rk);
        <DpHash as ComScheme<_>>::commit((&c1, &attribs.as_field()), &r.rc)
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
        DpEncrypt::encrypt(pk_enc, &message, rng)
    }

    fn receive(
        note: &Self::Note,
        ciphertext: &Self::Ciphertext,
        sk: &Self::SecretKey,
    ) -> Option<(Self::Attributes, Self::Randomness)> {
        let mut plaintext = Cursor::new(DpEncrypt::decrypt(&sk.1, ciphertext)?);
        let r = Self::Randomness::read(&mut plaintext).ok()?;
        let a = Attributes::read(&mut plaintext).ok()?;
        // Verify comm
        let a_pk = Self::derive_public_key(sk);
        let c1 = <DpHash as ComScheme<_>>::commit((&a_pk, &r.rn), &r.rk);
        let c2 = <DpHash as ComScheme<_>>::commit((&c1, &a.as_field()), &r.rc);
        if &c2 != note {
            None
        } else {
            Some((a, r))
        }
    }

    fn nul_eval((a_sk, _): &Self::SecretKey, r: &Self::Randomness) -> Self::Nullifier {
        let c1 = <DpHash as CompressionFunction<_>>::compress(a_sk, &r.rn);
        <DpHash as CompressionFunction<_>>::compress(&Self::DOMAIN_SEP_INVALIDATOR.into(), &c1)
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
                    ns!(cs, "rk"),
                    || Ok(r.borrow().rk),
                    mode,
                )?,
                rc: FpVar::<F>::new_variable(
                    ns!(cs, "rc"),
                    || Ok(r.borrow().rc),
                    mode,
                )?,
                rn: FpVar::<F>::new_variable(
                    ns!(cs, "rn"),
                    || Ok(r.borrow().rn),
                    mode,
                )?,
            })
        })
    }
}

pub struct AttributesVar {
    pub value: AllocatedNonNativeFieldVar<EmbeddedField, DpF>,
    pub type_: FpVar<DpF>,
}

impl AttributesVar {
    fn as_field(&self, params: &<DpHashGadget as ParameterGadget<DpF>>::ParametersVar) -> Result<FpVar<DpF>, SynthesisError> {
        let mut parts = self.value.limbs.clone();
        while parts.len() > 1 {
            let (a, b) = (parts.pop().unwrap(), parts.pop().unwrap());
            parts.push(<DpHashGadget as CompressionFunctionGadget<_,_,_,_>>::compress(&params, &a, &b)?);
        }
        <DpHashGadget as CompressionFunctionGadget<_,_,_,_>>::compress(&params, &parts[0], &self.type_)
    }
}

impl AllocVar<Attributes, DpF> for AttributesVar {
    fn new_variable<U: Borrow<Attributes>>(
        cs: impl Into<Namespace<DpF>>,
        f: impl FnOnce() -> Result<U, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into().cs();
        f().and_then(|a| {
            let value = AllocatedNonNativeFieldVar::<EmbeddedField, DpF>::new_variable(
                ark_relations::ns!(cs, "value"),
                || Ok(EmbeddedField::from(a.borrow().value)),
                mode,
            )?;
            let type_ = FpVar::<DpF>::new_variable(
                ark_relations::ns!(cs, "type"),
                || Ok(DpF::from(a.borrow().type_)),
                mode,
            )?;
            Ok(AttributesVar { value, type_ })
        })
    }
}

impl OTAGadget<DpF> for ZSwap {
    type KeyDeriveParams = <DpHashGadget as ParameterGadget<DpF>>::ParametersVar;
    type GenParams = <DpHashGadget as ParameterGadget<DpF>>::ParametersVar;
    type TagEvalParams = <DpHashGadget as ParameterGadget<DpF>>::ParametersVar;
    type SecretKeyVar = SecretKeyVar<DpF>;
    type PublicKeyVar = FpVar<DpF>;
    type RandomnessVar = RandomnessVar<DpF>;
    type AttributesVar = AttributesVar;
    type NoteVar = FpVar<DpF>;
    type NullifierVar = FpVar<DpF>;

    fn derive_public_key_gadget(
        hash_params: &Self::KeyDeriveParams,
        sk: &Self::SecretKeyVar,
    ) -> Result<Self::PublicKeyVar, SynthesisError> {
        let domain_sep_var = FpVar::Constant(Self::DOMAIN_SEP_PK_DERIV.into());
        <DpHashGadget as CompressionFunctionGadget<_,_,_,_>>::compress(hash_params, &domain_sep_var, &sk.0)
    }

    fn gen_gadget(
        params: &Self::GenParams,
        pk: &Self::PublicKeyVar,
        attribs: &Self::AttributesVar,
        r: &Self::RandomnessVar,
    ) -> Result<Self::NoteVar, SynthesisError> {
        let c1 = <DpHashGadget as ComSchemeGadget<_,_,_,_>>::commit(params, (pk, &r.rn), &r.rk)?;
        <DpHashGadget as ComSchemeGadget<_,_,_,_>>::commit(params, (&c1, &attribs.as_field(params)?), &r.rc)
    }

    fn nul_eval_gadget(
        params: &Self::TagEvalParams,
        sk: &Self::SecretKeyVar,
        r: &Self::RandomnessVar,
    ) -> Result<Self::NullifierVar, SynthesisError> {
        let c1 = <DpHashGadget as CompressionFunctionGadget<_,_,_,_>>::compress(params, &sk.0, &r.rn)?;
        let domain_sep_invalidator = FpVar::Constant(Self::DOMAIN_SEP_INVALIDATOR.into());
        <DpHashGadget as CompressionFunctionGadget<_,_,_,_>>::compress(params, &domain_sep_invalidator, &c1)
    }
}

const MERKLE_TREE_HEIGHT: usize = 32;

pub struct ZSwapState {
    notes: HashSet<<ZSwap as OneTimeAccount>::Note>,
    nullifiers: HashSet<<ZSwap as OneTimeAccount>::Nullifier>,
    merkle_tree: SparseMerkleTree<MerkleTreeConfig>,
    merkle_tree_next_index: usize,
    pub roots: Vec<DpF>,
}

impl ZSwapState {
    pub fn new() -> Self {
        let merkle_tree = SparseMerkleTree::blank(
            DpMerkleTree::leaf_param(),
            DpMerkleTree::compression_param(),
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

pub struct ZSwapPublicParams {
    spend_proving_key: <DpSNARK as SNARK<DpF>>::ProvingKey,
    spend_verifying_key: <DpSNARK as SNARK<DpF>>::VerifyingKey,
    output_proving_key: <DpSNARK as SNARK<DpF>>::ProvingKey,
    output_verifying_key: <DpSNARK as SNARK<DpF>>::VerifyingKey,
}

struct LangSpend {
    // Public inputs
    st: DpF,
    nul: DpF,
    com: GroupAffine<DpG>,

    // Witnesses
    path: Path<MerkleTreeConfig>,
    sk: DpF,
    type_: DpF,
    value: EmbeddedField,
    r: <ZSwap as OneTimeAccount>::Randomness,
    rc: EmbeddedField,
}

impl LangSpend {
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

impl ConstraintSynthesizer<DpF> for LangSpend {
    fn generate_constraints(self, cs: ConstraintSystemRef<DpF>) -> r1cs::Result<()> {
        let st = FpVar::new_input(ns!(cs, "st"), || Ok(self.st))?;
        let nul = FpVar::new_input(ns!(cs, "nul"), || Ok(self.nul))?;
        let com = AffineVar::<_, FpVar<DpF>>::new_input(ns!(cs, "com"), || Ok(self.com))?;

        let path =
            PathVar::<_, DpF, MerkleTreeConfigGadget>::new_witness(ns!(cs, "path"), || {
                Ok(self.path)
            })?;
        let sk = SecretKeyVar(FpVar::new_witness(ns!(cs, "sk"), || Ok(self.sk))?);
        let (_, type_wit) = DpHomComScheme::commit(&self.type_, &self.value, &self.rc);
        let type_ = FpVar::new_witness(ns!(cs, "type"), || Ok(self.type_))?;
        //let type_wit = NonNativeFieldVar::new_witness(ns!(cs, "type_wit"), || Ok(type_wit));
        let value: EmbeddedField = self.value.into();
        let value = AllocatedNonNativeFieldVar::new_witness(ns!(cs, "value"), || Ok(value))?;
        let r = RandomnessVar::new_witness(ns!(cs, "r"), || Ok(self.r))?;
        let rc = NonNativeFieldVar::new_witness(ns!(cs, "rc"), || Ok(self.rc))?;

        let params = DpHashGadget::allocate(ns!(cs, "poseidon-parameters"))?;
        let pk = ZSwap::derive_public_key_gadget(&params, &sk)?;
        let attribs = AttributesVar { type_, value };
        let note = ZSwap::gen_gadget(&params, &pk, &attribs, &r)?;

        let root2 = path.calculate_root(&params, &params, &[note][..])?;
        st.enforce_equal(&root2)?;

        // let com2 = DpHomComSchemeGadget::verify(type_, type_wit,

        unimplemented!()
    }
}

struct LangOutput {
    // Public inputs
    pk: DpF,
    note: DpF,
    com: GroupAffine<DpG>,

    // Witnesses
    type_: DpF,
    value: EmbeddedField,
    r: <ZSwap as OneTimeAccount>::Randomness,
    rc: EmbeddedField
}

impl LangOutput {
    fn new() -> Self {
        unimplemented!()
    }
}

impl ConstraintSynthesizer<DpF> for LangOutput {
    fn generate_constraints(self, cs: ConstraintSystemRef<DpF>) -> r1cs::Result<()> {
        unimplemented!()
    }
}


// wrappers to implement missing traits?
//struct ProofW(<DpSNARK as SNARK<DpF>>::Proof); // try wrapping?
//struct HomComW(GroupAffine<DpG>);


pub struct ZSwapSignature {
    pub input_signatures: HashSet<(
        Proof,
        HomCom,
        <ZSwap as OneTimeAccount>::Nullifier,
    )>,
    pub output_signatures: HashSet<(
        Proof,
        HomCom,
        (
            <ZSwap as OneTimeAccount>::Note,
            <ZSwap as OneTimeAccount>::Ciphertext,
        ),
    )>,
    pub randomness: EmbeddedField,
}

pub enum ZSwapError {
    ZSwapErrorStr(&'static str),
    ZSwapErrorCircuit(<DpSNARK as SNARK<DpF>>::Error)
}

impl ZSwapScheme for ZSwap
//where
//    EmbeddedField: Hash,
//    HomCom: Hash + Clone,
//    Proof: Eq + Hash,
{
    type PublicParameters = ZSwapPublicParams;
    type Signature = ZSwapSignature;
    type State = ZSwapState;
    type StateWitness = Path<MerkleTreeConfig>;
    type Error = ZSwapError;

    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self::PublicParameters, Self::Error> {
        let (spend_proving_key, spend_verifying_key) =
            DpSNARK::setup(LangSpend::new(), rng)
            .map_err(ZSwapError::ZSwapErrorCircuit)?;
        let (output_proving_key, output_verifying_key) =
            DpSNARK::setup(LangOutput::new(), rng)
            .map_err(ZSwapError::ZSwapErrorCircuit)?;
        Ok(ZSwapPublicParams {
            spend_proving_key,
            spend_verifying_key,
            output_proving_key,
            output_verifying_key,
        })
    }

    fn sign_tx<R: Rng + CryptoRng + Sized>(
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

        let rc_s: Vec<EmbeddedField> =
            (0..inputs.len()).map(|_| UniformRand::rand(rng)).collect();
        let com_s: Vec<DpHomCom> =
            inputs.iter().zip(rc_s.iter())
            .map(|(input,rc)|
              <DpHomComScheme as
               HomComScheme<_,_,_>>::
                 commit(&From::from(input.4.type_),
                        &From::from(input.4.value),
                        &rc).0)
            .collect();

        let rc_t: Vec<EmbeddedField> =
            (0..inputs.len()).map(|_| UniformRand::rand(rng)).collect();
        let com_t: Vec<DpHomCom> =
            outputs.iter().zip(rc_t.iter())
            .map(|(output,rc)|
              <DpHomComScheme as
               HomComScheme<_,_,_>>::
                 commit(&From::from(output.2.type_),
                        &From::from(output.2.value),
                        &rc).0)
            .collect();


        let mut proofs_s: Vec<Proof> = Vec::new();
        for i in 0..inputs.len() {
            // part of params
            let st: DpF = state.roots.last().ok_or(ZSwapError::ZSwapErrorStr("bla"))?.clone();
            let circuit = LangSpend {
                // Public inputs
                st: st,
                nul: inputs[i].2,
                com: com_s[i],

                // Witnesses
                path: inputs[i].3.clone(),
                sk: inputs[i].0.0,
                // @volhovm: I'm a bit worried about these conversions.
                // Is input field smaller than the output one? i.e. is `from` injective?
                type_: From::from(inputs[i].4.type_),
                value: From::from(inputs[i].4.value),
                r: inputs[i].5.clone(),
                rc: rc_s[i]
            };
            let proof =
                <DpSNARK as SNARK<DpF>>::prove(&params.spend_proving_key,
                                                       circuit,
                                                       rng)
                .map_err(ZSwapError::ZSwapErrorCircuit)?;
            proofs_s.push(proof);
        }

        let mut proofs_s: Vec<Proof> = Vec::new();
        for i in 0..inputs.len() {
            // part of params
            let st: DpF = state.roots.last().ok_or(ZSwapError::ZSwapErrorStr("bla"))?.clone();
            let circuit = LangSpend {
                // Public inputs
                st: st,
                nul: inputs[i].2,
                com: com_s[i],

                // Witnesses
                path: inputs[i].3.clone(),
                sk: inputs[i].0.0,
                // @volhovm: I'm a bit worried about these conversions.
                // Is input field smaller than the output one? i.e. is `from` injective?
                type_: From::from(inputs[i].4.type_),
                value: From::from(inputs[i].4.value),
                r: inputs[i].5.clone(),
                rc: rc_s[i]
            };
            let proof =
                <DpSNARK as SNARK<DpF>>::prove(&params.spend_proving_key,circuit,rng)
                .map_err(ZSwapError::ZSwapErrorCircuit)?;
            proofs_s.push(proof);
        }


        let mut proofs_t: Vec<Proof> = Vec::new();
        for i in 0..outputs.len() {
            let circuit = LangOutput {
                // Public inputs
                pk: outputs[i].0.0,
                note: outputs[i].1,
                com: com_t[i],

                // Witnesses
                type_: From::from(outputs[i].2.type_),
                value: From::from(outputs[i].2.value),
                r: outputs[i].3.clone(),
                rc: rc_t[i]
            };
            let proof =
                <DpSNARK as SNARK<DpF>>::prove(&params.spend_proving_key,circuit,rng)
                .map_err(ZSwapError::ZSwapErrorCircuit)?;
            proofs_t.push(proof);
        }


        let mut input_signatures: HashSet<(
            Proof,
            DpHomCom,
            Self::Nullifier)> = HashSet::new();
        for i in 0..outputs.len() {
            // The thing must satisfy Eq,Hash but it doesn't
            // input_signatures.insert((proofs_s[i],com_s[i],inputs[i].2));
        }
        let output_signatures: HashSet<(
            Proof,
            DpHomCom,
            (Self::Note,
             Self::Ciphertext))> = HashSet::new();
        let randomness: EmbeddedField =
            rc_s.iter().fold(From::from(0),|x:EmbeddedField,y| x + y) -
            rc_t.iter().fold(From::from(0),|x:EmbeddedField,y| x + y);

        Ok(ZSwapSignature {
            input_signatures,
            output_signatures,
            randomness })
    }

    fn verify_tx<R: Rng + CryptoRng + ?Sized>(
        params: &Self::PublicParameters,
        state: &Self::State,
        transaction: &Transaction<Self>,
        signature: &Self::Signature,
        rng: &mut R,
    ) -> Result<bool, Self::Error> {

        let com_one: HomCom = Zero::zero();
        let input_minus_output: HomCom =
            signature.input_signatures.iter()
            .map(|(_,com,_)| com.clone()).chain(
                signature.output_signatures.iter()
                .map(|(_,com,_)| -com.clone()))
            .fold(com_one,|x,y| x + y);

        let com_rc: HomCom =
              <DpHomComScheme as
               HomComScheme::<_,_,_>>::
                 commit(&<DpF as Zero>::zero(),
                        &<EmbeddedField as Zero>::zero(),
                        &signature.randomness).0;

        let deltas_coms: HomCom =
            transaction.deltas.iter()
            .map(|(type_,val)|
              <DpHomComScheme as
               HomComScheme::<_,_,_>>::
                 commit(&<DpF as From<u64>>::from(type_.clone()),
                        &<EmbeddedField as From<i128>>::from(val.clone()),
                        &<EmbeddedField as Zero>::zero()).0)
            .fold(com_one,|x,y| x + y);


        let coms_check = input_minus_output - com_rc - deltas_coms == com_one;

        return Ok(coms_check);
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
        unimplemented!()

        // The issue with the code below is that signature elements don't
        // implement Eq/Hash/Clone, so we need wrappers probably.

//        let mut input_signatures = HashSet::new();
//        let mut output_signatures = HashSet::new();
//        let mut randomness = EmbeddedField::zero();
//        for sig in signatures {
//            input_signatures.extend(sig.input_signatures.iter().cloned());
//            output_signatures.extend(sig.output_signatures.iter().cloned());
//            randomness += sig.randomness;
//        }
//        Ok(ZSwapSignature {
//            input_signatures,
//            output_signatures,
//            randomness,
//        })
    }
}
