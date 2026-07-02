#![no_main]

use parity_scale_codec::Encode;
use risc0_zkvm::guest::env;
use rsa_risc0::pkcs1v15::{Signature as RsaSignature, VerifyingKey};
use rsa_risc0::signature::Verifier;
use rsa_risc0::{BigUint, RsaPublicKey};
use sha2_risc0::{Digest, Sha256};

risc0_zkvm::guest::entry!(main);

const DEPTH: usize = 45;
const MAX_INPUT_NOTES: usize = 8;
const MAX_OUTPUT_NOTES: usize = 8;

const RSA_MODULUS_BYTES: usize = 256;
const NULLIFIER_BYTES: usize = 32;
const SECRET_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 256;

const RSA_E: u32 = 65537;

#[derive(Clone)]
struct Note {
    value: u128,
    owner_modulus: [u8; RSA_MODULUS_BYTES],
    nullifier: [u8; NULLIFIER_BYTES],
    secret: [u8; SECRET_BYTES],
}

#[derive(Clone, Encode)]
struct TransferJournal {
    root: [u8; 32],
    nullifiers: Vec<[u8; 32]>,
    output_leaves: Vec<[u8; 32]>,
}

#[allow(dead_code)]
#[derive(Clone, Encode)]
struct TransferPublicOutputs {
    root: [u8; 32],
    nullifiers: Vec<[u8; 32]>,
    output_leaves: Vec<[u8; 32]>,
}

fn main() {
    let root = read_32();

    let input_count: u32 = env::read();
    let output_count: u32 = env::read();

    assert!(input_count > 0);
    assert!(output_count > 0);
    assert!((input_count as usize) <= MAX_INPUT_NOTES);
    assert!((output_count as usize) <= MAX_OUTPUT_NOTES);

    let mut input_sum = 0u128;
    let mut input_leaves = Vec::<[u8; 32]>::with_capacity(input_count as usize);
    let mut nullifiers = Vec::<[u8; 32]>::with_capacity(input_count as usize);

    let mut owner_modulus: Option<[u8; RSA_MODULUS_BYTES]> = None;

    for _ in 0..input_count {
        let leaf_index: u64 = env::read();
        let note = read_note();

        if let Some(first_owner_modulus) = owner_modulus {
            assert_eq!(note.owner_modulus, first_owner_modulus);
        } else {
            owner_modulus = Some(note.owner_modulus);
        }

        let mut merkle_path = [[0u8; 32]; DEPTH];
        for sibling in merkle_path.iter_mut() {
            env::read_slice(sibling);
        }

        let leaf = note_leaf(&note);
        let computed_root = compute_root(leaf, leaf_index, &merkle_path);

        assert_eq!(computed_root, root);

        input_sum = input_sum.checked_add(note.value).unwrap();

        input_leaves.push(leaf);
        nullifiers.push(note.nullifier);
    }

    assert_unique_nullifiers(&nullifiers);

    let mut output_sum = 0u128;
    let mut output_leaves = Vec::<[u8; 32]>::with_capacity(output_count as usize);

    for _ in 0..output_count {
        let note = read_note();

        output_sum = output_sum.checked_add(note.value).unwrap();
        output_leaves.push(note_leaf(&note));
    }

    assert_eq!(input_sum, output_sum);

    let action_hash = hash_transfer_action(&root, &input_leaves, &nullifiers, &output_leaves);

    let mut signature_bytes = [0u8; SIGNATURE_BYTES];
    env::read_slice(&mut signature_bytes);

    verify_owner_signature(owner_modulus.unwrap(), &action_hash, &signature_bytes);

    let journal = TransferJournal {
        root,
        nullifiers,
        output_leaves,
    }
    .encode();

    env::commit_slice(&journal);
}

fn read_note() -> Note {
    let value: u128 = env::read();

    let mut owner_modulus = [0u8; RSA_MODULUS_BYTES];
    env::read_slice(&mut owner_modulus);

    let nullifier = read_32();
    let secret = read_32();

    Note {
        value,
        owner_modulus,
        nullifier,
        secret,
    }
}

fn read_32() -> [u8; 32] {
    let mut out = [0u8; 32];
    env::read_slice(&mut out);
    out
}

fn note_leaf(note: &Note) -> [u8; 32] {
    let mut h = Sha256::new();

    h.update(b"stellar-mixer-note-leaf-v1");
    h.update(note.value.to_be_bytes());
    h.update(note.owner_modulus);
    h.update(note.nullifier);
    h.update(note.secret);

    h.finalize().into()
}

fn hash_node(level: u32, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();

    h.update(b"stellar-mixer-node-v1");
    h.update(level.to_be_bytes());
    h.update(left);
    h.update(right);

    h.finalize().into()
}

fn compute_root(mut leaf: [u8; 32], leaf_index: u64, path: &[[u8; 32]; DEPTH]) -> [u8; 32] {
    for (level, sibling) in path.iter().enumerate() {
        let bit = (leaf_index >> level) & 1;

        leaf = if bit == 0 {
            hash_node(level as u32, &leaf, sibling)
        } else {
            hash_node(level as u32, sibling, &leaf)
        };
    }

    leaf
}

fn assert_unique_nullifiers(nullifiers: &[[u8; 32]]) {
    for i in 0..nullifiers.len() {
        for j in (i + 1)..nullifiers.len() {
            assert_ne!(nullifiers[i], nullifiers[j]);
        }
    }
}

fn hash_transfer_action(
    root: &[u8; 32],
    input_leaves: &[[u8; 32]],
    nullifiers: &[[u8; 32]],
    output_leaves: &[[u8; 32]],
) -> [u8; 32] {
    let mut h = Sha256::new();

    h.update(b"stellar-mixer-transfer-action-v1");
    h.update(root);

    h.update((input_leaves.len() as u32).to_be_bytes());
    for leaf in input_leaves {
        h.update(leaf);
    }

    h.update((nullifiers.len() as u32).to_be_bytes());
    for nullifier in nullifiers {
        h.update(nullifier);
    }

    h.update((output_leaves.len() as u32).to_be_bytes());
    for leaf in output_leaves {
        h.update(leaf);
    }

    h.finalize().into()
}

fn verify_owner_signature(
    owner_modulus: [u8; RSA_MODULUS_BYTES],
    action_hash: &[u8; 32],
    signature_bytes: &[u8; SIGNATURE_BYTES],
) {
    let public_key =
        RsaPublicKey::new(BigUint::from_bytes_be(&owner_modulus), BigUint::from(RSA_E)).unwrap();

    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    let signature = RsaSignature::try_from(&signature_bytes[..]).unwrap();

    verifying_key.verify(action_hash, &signature).unwrap();
}
