#![allow(dead_code)]

use crate::halo2::pasta::Fp;

use crate::{
    franchise::FranchiseCircuit,
    primitives::poseidon::{self, ConstantLength, P128Pow5T3},
};

pub struct MerkleTree {
    depth: u32,
    nodes: Vec<Fp>,
}

impl MerkleTree {
    pub fn new(depth: u32) -> Self {
        let size = 2usize.pow(depth - 1);
        Self {
            depth,
            nodes: Vec::with_capacity(2 * size - 1),
        }
    }
    pub fn insert(&mut self, value: Fp) -> usize {
        assert!(self.nodes.len() < 2usize.pow(self.depth - 1));
        self.nodes.push(value);
        self.nodes.len() - 1
    }

    fn hash(first: Fp, second: Fp) -> Fp {
        poseidon::Hash::init(P128Pow5T3, ConstantLength::<2>).hash([first, second])
    }

    pub fn calc(&mut self) {
        // fill with zeroes the unused leafs
        let size = 2usize.pow(self.depth - 1);
        if self.nodes.len() < size {
            self.nodes.resize(size, Fp::zero());
        }

        // compute the merkle tree nodes
        let mut i = 0;
        while i < self.nodes.capacity() - 1 {
            self.nodes
                .push(Self::hash(self.nodes[i], self.nodes[i + 1]));
            i += 2;
        }
    }

    pub fn print_tree(&self) {
        let mut pos = (self.nodes.len() - 1) as isize;
        let mut lvl = 1;
        while pos >= 0 {
            for l in 0..lvl {
                let s = format!("{:?}", self.nodes[(pos + l) as usize]);
                print!("{} ", &s[60..66]);
            }
            println!("");
            pos -= lvl * 2;
            lvl *= 2;
        }
    }

    pub fn root(&self) -> Fp {
        self.nodes[self.nodes.len() - 1]
    }
    pub fn get(&self, index: usize) -> Fp {
        self.nodes[index]
    }

    pub fn witness(&self, mut index: usize) -> Vec<(Fp, bool)> {
        let mut base = 0;
        let mut siblings = Vec::new();
        for n in 0..self.depth - 1 {
            let left_right = 1 - (index & 1);
            siblings.push((
                self.nodes[base + (index & 0xfffe) + left_right],
                left_right == 1,
            ));
            base += 2usize.pow(self.depth - n - 1);
            index >>= 1;
        }
        siblings
    }

    pub fn check_witness(value: Fp, siblings: Vec<(Fp, bool)>, root: Fp) -> bool {
        let mut hash = value;
        for (value, order) in siblings {
            hash = if order {
                Self::hash(hash, value)
            } else {
                Self::hash(value, hash)
            };
        }
        hash == root
    }
}

pub fn generate_circuit_inputs<const LVL: usize>(
    secret_key: Fp,
    process_id: [Fp; 2],
    vote_hash: Fp,
    witness: &[(Fp, bool)],
) -> (FranchiseCircuit<LVL>, Fp) {
    let process_id_hash =
        poseidon::Hash::init(P128Pow5T3, ConstantLength::<2>).hash([process_id[0], process_id[1]]);

    let pub_nullifier =
        poseidon::Hash::init(P128Pow5T3, ConstantLength::<2>).hash([secret_key, process_id_hash]);

    let mut pri_siblings = [Fp::zero(); LVL];
    let mut pri_index = [false; LVL];
    for (n, (l, p)) in witness.iter().enumerate() {
        pri_siblings[n] = *l;
        pri_index[n] = !p;
    }

    let circuit = FranchiseCircuit {
        pri_index: Some(pri_index),
        pri_siblings: Some(pri_siblings),
        pri_secret_key: Some(secret_key),
        pub_processid: Some(process_id),
        pub_votehash: Some(vote_hash),
    };

    (circuit, pub_nullifier)
}

pub fn generate_test_data<const LVL: usize>() -> (FranchiseCircuit<LVL>, Vec<Fp>) {
    let secret_key = Fp::from(8);
    let process_id = [Fp::from(6), Fp::from(7)];
    let vote_hash = Fp::from(1);
    let public_key = secret_to_public_key(secret_key);

    let mut root = public_key;
    let mut witness = Vec::new();
    for n in 0..LVL as u64 {
        let direction = n % 2 == 0;
        let value = Fp::from(n);
        let (left, right) = if direction {
            (root, value)
        } else {
            (value, root)
        };

        let digest = poseidon::Hash::init(P128Pow5T3, ConstantLength::<2>).hash([left, right]);
        witness.push((value, direction));
        root = digest;
    }
    assert!(MerkleTree::check_witness(public_key, witness.clone(), root));

    let (circuit, nullifier) =
        generate_circuit_inputs::<LVL>(secret_key, process_id, vote_hash, &witness);

    (circuit, vec![root, nullifier, vote_hash])
}

pub fn secret_to_public_key(secret_key: Fp) -> Fp {
    poseidon::Hash::init(P128Pow5T3, ConstantLength::<2>).hash([secret_key, secret_key])
}

#[test]
fn simple_mt_test() {
    let mut tree = MerkleTree::new(6);
    for n in 0..2u64.pow(tree.depth - 1) {
        tree.insert(Fp::from(n));
    }
    tree.calc();
    tree.print_tree();
    for n in 0..2usize.pow(tree.depth - 1) {
        let witness = tree.witness(n);
        assert!(MerkleTree::check_witness(tree.get(n), witness, tree.root()));
    }
}
