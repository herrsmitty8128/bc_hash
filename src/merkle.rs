// Copyright (c) 2023 herrsmitty8128
// Distributed under the MIT software license, see the accompanying
// file LICENSE.txt or http://www.opensource.org/licenses/mit-license.php.

use crate::error;
use crate::OneWayHasher;

/// Calculates the merkle root for a vector of leaves where each leaf is the hash digest of
/// a record in a block of data. This function reduces the ```leaves``` argument down to a
/// single element in the vector, which is the root. It returns a ```bool``` value indicating
/// whether or not a mutation was encountered during the calculation.
pub fn compute_root<const MDLEN: usize, H>(leaves: &mut Vec<[u8; MDLEN]>) -> error::Result<bool>
where
    H: OneWayHasher<MDLEN>,
{
    let mut mutation: bool = false;
    let mut hasher: H = H::init();
    while leaves.len() > 1 {
        for i in 0..leaves.len() - 1 {
            // search for a mutation and set the mutation variable to true if we find one
            if leaves[i] == leaves[i + 1] {
                mutation = true;
            }
        }
        if leaves.len() & 1 != 0 {
            // the vector contains an odd number of leaves, so copy and append the last leaf to make it an even number.
            match leaves.last() {
                Some(d) => leaves.push(*d),
                None => return Err(error::Error::InvalidMerkleLeaves), // should never get here
            }
        }
        for i in 0..(leaves.len() / 2) {
            hasher
                .update(&leaves[i * 2])
                .update(&leaves[i * 2 + 1])
                .finish(&mut leaves[i]);
        }
        leaves.truncate(leaves.len() / 2)
    }
    Ok(mutation)
}

pub enum ChildNode<const MDLEN: usize> {
    Left([u8; MDLEN]),
    Right([u8; MDLEN]),
}

pub type Proof<const MDLEN: usize> = Vec<ChildNode<MDLEN>>;

pub fn compute_proof<const MDLEN: usize, H>(
    leaves: &mut Vec<[u8; MDLEN]>,
    mut index: usize,
) -> error::Result<(Proof<MDLEN>, bool)>
where
    H: OneWayHasher<MDLEN>,
{
    let mut mutation: bool = false;
    let mut proof: Proof<MDLEN> = Proof::new();
    let mut hasher: H = H::init();
    if index >= leaves.len() {
        Err(error::Error::InvalidIndex)
    } else {
        while leaves.len() > 1 {
            for i in 0..leaves.len() - 1 {
                if leaves[i] == leaves[i + 1] {
                    mutation = true;
                }
            }
            if leaves.len() & 1 != 0 {
                match leaves.last() {
                    Some(d) => leaves.push(*d),
                    None => return Err(error::Error::InvalidMerkleLeaves),
                }
            }
            proof.push(if index & 1 == 1 {
                ChildNode::Left(leaves[index ^ 1])
            } else {
                ChildNode::Right(leaves[index ^ 1])
            });
            for i in 0..(leaves.len() / 2) {
                hasher
                    .update(&leaves[i * 2])
                    .update(&leaves[i * 2 + 1])
                    .finish(&mut leaves[i]);
            }
            leaves.truncate(leaves.len() / 2);
            index >>= 1;
        }
        Ok((proof, mutation))
    }
}

pub fn prove<const MDLEN: usize, H>(proof: Proof<MDLEN>, digest: &mut [u8; MDLEN])
where
    H: OneWayHasher<MDLEN>,
{
    let mut hasher: H = H::init();
    for node in proof.iter() {
        match node {
            ChildNode::Left(sibling) => {
                hasher.update(sibling).update(&digest[..]).finish(digest);
            }
            ChildNode::Right(sibling) => {
                hasher.update(&digest[..]).update(sibling).finish(digest);
            }
        }
    }
}
