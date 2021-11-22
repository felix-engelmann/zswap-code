use ark_crypto_primitives::merkle_tree::{Config, DigestConverter, LeafParam, Path, TwoToOneParam};
use ark_crypto_primitives::{crh::TwoToOneCRHScheme, CRHScheme, Error};
use std::error::Error as StdError;
use std::fmt::{self, Debug, Display, Formatter};
use std::rc::Rc;

pub struct SparseMerkleTree<P: Config>(MerkleTreeNode<P>);

impl<P: Config> Debug for SparseMerkleTree<P> where P::LeafDigest: Debug {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        self.0.fmt(f)
    }
}

enum MerkleTreeNode<P: Config> {
    Leaf {
        hash: P::LeafDigest,
        params: Rc<Params<P>>,
    },
    Stub {
        height: usize,
        params: Rc<Params<P>>,
    },
    Node {
        hash: P::InnerDigest,
        left: Box<MerkleTreeNode<P>>,
        right: Box<MerkleTreeNode<P>>,
        height: usize,
        params: Rc<Params<P>>,
    },
}

impl<P: Config> Debug for MerkleTreeNode<P> where P::LeafDigest: Debug {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        for (path, leaf) in self.leaves() {
            writeln!(f, "{}: {:?}", path.into_iter().map(|b| if b { "r" } else { "l" }).collect::<Vec<_>>().join(""), leaf)?;
        }
        Ok(())
    }
}

impl<P: Config> Clone for MerkleTreeNode<P> {
    fn clone(&self) -> Self {
        match self {
            Leaf { hash, params } => Leaf {
                hash: hash.clone(),
                params: params.clone(),
            },
            Stub { height, params } => Stub {
                height: *height,
                params: params.clone(),
            },
            Node {
                hash,
                left,
                right,
                height,
                params,
            } => Node {
                hash: hash.clone(),
                left: left.clone(),
                right: right.clone(),
                height: *height,
                params: params.clone(),
            },
        }
    }
}

impl<P: Config> MerkleTreeNode<P> {
    fn leaves(&self) -> Vec<(Vec<bool>, P::LeafDigest)> {
        match self {
            Leaf { hash, .. } => vec![(Vec::new(), hash.clone())],
            Stub { .. } => Vec::new(),
            Node { left, right, .. } => {
                left.leaves().into_iter().map(|(mut path, digest)| {
                    path.push(false);
                    (path, digest)
                }).chain(right.leaves().into_iter().map(|(mut path, digest)| {
                    path.push(true);
                    (path, digest)
                })).collect()
            }
        }
    }

    fn new(height: usize, params: Rc<Params<P>>) -> Self {
        if height == 0 {
            Leaf {
                hash: P::LeafDigest::default(),
                params,
            }
        } else {
            Stub { height, params }
        }
    }

    fn height(&self) -> usize {
        match self {
            Leaf { .. } => 0,
            Stub { height, .. } => *height,
            Node { height, .. } => *height,
        }
    }

    fn root(&self) -> P::InnerDigest {
        match self {
            Leaf { .. } => panic!("Cannot retrieve root of a Merkle tree leaf!"),
            Stub { .. } => P::InnerDigest::default(),
            Node { hash, .. } => hash.clone(),
        }
    }

    fn from_leaf(&self) -> P::LeafDigest {
        match self {
            Leaf { hash, .. } => hash.clone(),
            _ => unreachable!(),
        }
    }

    pub fn update(&mut self, index: usize, new_leaf: &P::Leaf) -> Result<(), Error> {
        let h = self.height();
        if let Leaf { hash, params } = self {
            *hash = P::LeafHash::evaluate(&params.leaf_hash, new_leaf)?;
            return Ok(());
        }
        if let Stub { height, params } = self {
            let new = Box::new(Self::new(*height - 1, params.clone()));
            *self = Node {
                hash: P::InnerDigest::default(),
                left: new.clone(),
                right: new,
                height: *height,
                params: params.clone(),
            };
        }
        if let Node {
            hash,
            left,
            right,
            height,
            params,
        } = self
        {
            let cmp = 1 << (h - 1);
            if index < cmp {
                left.update(index, new_leaf)?;
            } else {
                right.update(index - cmp, new_leaf)?;
            }
            if *height == 1 {
                *hash = P::TwoToOneHash::evaluate(
                    &params.two_to_one_hash,
                    P::LeafInnerDigestConverter::convert(left.from_leaf())?,
                    P::LeafInnerDigestConverter::convert(right.from_leaf())?,
                )?;
            } else {
                *hash =
                    P::TwoToOneHash::compress(&params.two_to_one_hash, left.root(), right.root())?;
            }
            Ok(())
        } else {
            unreachable!()
        }
    }
}

struct Params<P: Config> {
    leaf_hash: LeafParam<P>,
    two_to_one_hash: TwoToOneParam<P>,
}

use MerkleTreeNode::*;

#[derive(Debug)]
pub struct InvalidIndex(usize);

impl Display for InvalidIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "Invalid index into sparse merkle tree: {}", self.0)
    }
}

impl StdError for InvalidIndex {}

impl<P: Config> SparseMerkleTree<P> {
    pub fn blank(
        leaf_hash_param: &LeafParam<P>,
        two_to_one_hash_param: &TwoToOneParam<P>,
        height: usize,
    ) -> Self {
        let params = Rc::new(Params {
            leaf_hash: leaf_hash_param.clone(),
            two_to_one_hash: two_to_one_hash_param.clone(),
        });
        SparseMerkleTree(Stub { height, params })
    }

    pub fn height(&self) -> usize {
        self.0.height()
    }

    pub fn root(&self) -> P::InnerDigest {
        self.0.root()
    }

    pub fn generate_proof(&self, index: usize) -> Result<Path<P>, Error> {
        let mut at = &self.0;
        let mut i = index;
        assert!(
            at.height() > 1,
            "Cannot prove a path in tree smaller than 2."
        );
        let mut path = Vec::with_capacity(at.height() - 2);
        while at.height() > 1 {
            let cmp = 1 << (at.height() - 1);
            let nxt = match at {
                Leaf { .. } => unreachable!(),
                Stub { .. } => return Err(Box::new(InvalidIndex(index))),
                Node { left, right, .. } => {
                    if i < cmp {
                        path.push(right.root());
                        left
                    } else {
                        path.push(left.root());
                        i -= cmp;
                        right
                    }
                }
            };
            at = nxt;
        }
        let sibling = match (i, at) {
            (_, Stub { .. }) => return Err(Box::new(InvalidIndex(index))),
            (0, Node { right, .. }) => right.from_leaf(),
            (1, Node { left, .. }) => left.from_leaf(),
            _ => unreachable!(),
        };
        Ok(Path {
            leaf_sibling_hash: sibling,
            auth_path: path,
            leaf_index: index,
        })
    }

    pub fn update(&mut self, index: usize, new_leaf: &P::Leaf) -> Result<(), Error> {
        self.0.update(index, new_leaf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon::Poseidon;
    use crate::primitives::MerkleTreeParams;
    use ark_bls12_381::Fr;
    use ark_crypto_primitives::crh::poseidon::{TwoToOneCRH, CRH};

    type Params = <Poseidon as MerkleTreeParams<Fr, CRH<Fr>, TwoToOneCRH<Fr>>>::Config;
    #[test]
    fn test_membership() {
        let mut tree = SparseMerkleTree::<Params>::blank(
            Params::leaf_param(),
            Params::compression_param(),
            32,
        );
        tree.update(0, &[42.into()][..]).unwrap();
        tree.update(0, &[41.into()][..]).unwrap();
        tree.update(3, &[43.into()][..]).unwrap();
        tree.update(62, &[12.into()][..]).unwrap();
        assert!(tree
            .generate_proof(0)
            .unwrap()
            .verify(
                Params::leaf_param(),
                Params::compression_param(),
                &tree.root(),
                &[41.into()][..]
            )
            .unwrap());
        assert!(tree
            .generate_proof(3)
            .unwrap()
            .verify(
                Params::leaf_param(),
                Params::compression_param(),
                &tree.root(),
                &[43.into()][..]
            )
            .unwrap());
        assert!(tree
            .generate_proof(62)
            .unwrap()
            .verify(
                Params::leaf_param(),
                Params::compression_param(),
                &tree.root(),
                &[12.into()][..]
            )
            .unwrap());
    }
}
