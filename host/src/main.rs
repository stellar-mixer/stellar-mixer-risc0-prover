use anyhow::{ensure, Result};
use methods::{TRANSFER_GUEST_ID, WITHDRAW_GUEST_ELF, WITHDRAW_GUEST_ID};
use parity_scale_codec::Decode;
use rand_core::{OsRng, RngCore};
use risc0_zkvm::{default_prover, ExecutorEnv, ExecutorEnvBuilder, ProverOpts};
use rsa_risc0::pkcs1v15::{SigningKey, VerifyingKey};
use rsa_risc0::signature::{SignatureEncoding, Signer, Verifier};
use rsa_risc0::traits::PublicKeyParts;
use rsa_risc0::{RsaPrivateKey, RsaPublicKey};
use sha2_risc0::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

const DEPTH: usize = 45;

const RSA_MODULUS_BYTES: usize = 256;
const NULLIFIER_BYTES: usize = 32;
const SECRET_BYTES: usize = 32;
const SIGNATURE_BYTES: usize = 256;

const RSA_E_BYTES: [u8; 3] = [0x01, 0x00, 0x01];

#[derive(Clone)]
struct Note {
    value: u128,
    owner_modulus: [u8; RSA_MODULUS_BYTES],
    nullifier: [u8; NULLIFIER_BYTES],
    secret: [u8; SECRET_BYTES],
}

#[derive(Debug, Decode)]
struct WithdrawJournal {
    root: [u8; 32],
    nullifiers: Vec<[u8; 32]>,
    withdraw_amount: u128,
    output_leaf: [u8; 32],
}

fn main() -> Result<()> {
    println!("================ STELLAR MIXER RISC ZERO PROVER ================");
    println!("purpose: image IDs + withdraw STARK proving benchmark");
    println!("tree depth: {}", DEPTH);
    println!();

    println!("transfer image id words: {:?}", TRANSFER_GUEST_ID);
    println!(
        "transfer image id hex le-words: {}",
        image_id_hex_le_words(TRANSFER_GUEST_ID)
    );

    println!("withdraw image id words: {:?}", WITHDRAW_GUEST_ID);
    println!(
        "withdraw image id hex le-words: {}",
        image_id_hex_le_words(WITHDRAW_GUEST_ID)
    );
    println!();

    run_withdraw_stark_benchmark()?;

    Ok(())
}

fn run_withdraw_stark_benchmark() -> Result<()> {
    println!("---------------- WITHDRAW STARK PROVE BENCHMARK ----------------");

    let total_start = Instant::now();

    let setup_start = Instant::now();

    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
    let public_key = RsaPublicKey::from(&private_key);

    ensure!(
        public_key.e().to_bytes_be().as_slice() == RSA_E_BYTES.as_slice(),
        "unexpected RSA exponent"
    );

    let owner_modulus: [u8; RSA_MODULUS_BYTES] = fixed_be_array(&public_key.n().to_bytes_be())?;

    let input_notes = vec![
        random_note(70, owner_modulus, &mut rng),
        random_note(30, owner_modulus, &mut rng),
    ];

    let withdraw_amount = 45u128;
    let change_note = random_note(55, owner_modulus, &mut rng);

    let input_indices = vec![19usize, 43usize];

    let input_sum: u128 = input_notes.iter().map(|note| note.value).sum();
    let expected_total = withdraw_amount
        .checked_add(change_note.value)
        .ok_or_else(|| anyhow::anyhow!("withdraw amount + change overflow"))?;

    ensure!(
        input_sum == expected_total,
        "demo withdraw value mismatch: input_sum={input_sum}, expected_total={expected_total}"
    );

    let input_leaves: Vec<[u8; 32]> = input_notes.iter().map(note_leaf).collect();
    let nullifiers: Vec<[u8; 32]> = input_notes.iter().map(|note| note.nullifier).collect();
    let output_leaf = note_leaf(&change_note);

    let indexed_input_leaves: Vec<(usize, [u8; 32])> = input_indices
        .iter()
        .copied()
        .zip(input_leaves.iter().copied())
        .collect();

    let (root, paths) = build_sparse_tree(&indexed_input_leaves)?;

    let action_hash = hash_withdraw_action(
        &root,
        &input_leaves,
        &nullifiers,
        withdraw_amount,
        &output_leaf,
    );

    let signature_bytes = sign_action(&private_key, &public_key, &action_hash)?;

    let setup_time = setup_start.elapsed();

    let env_start = Instant::now();

    let mut builder = ExecutorEnv::builder();

    builder.write_slice(&root);
    builder.write(&(input_notes.len() as u32))?;

    for i in 0..input_notes.len() {
        builder.write(&(input_indices[i] as u64))?;
        write_note(&mut builder, &input_notes[i])?;

        for sibling in paths[i].iter() {
            builder.write_slice(sibling);
        }
    }

    builder.write(&withdraw_amount)?;
    write_note(&mut builder, &change_note)?;
    builder.write_slice(&signature_bytes);

    let env = builder.build()?;

    let env_time = env_start.elapsed();

    let prove_start = Instant::now();

    let stark_receipt = default_prover()
        .prove_with_opts(env, WITHDRAW_GUEST_ELF, &ProverOpts::composite())?
        .receipt;

    let prove_time = prove_start.elapsed();

    let verify_start = Instant::now();
    stark_receipt.verify(WITHDRAW_GUEST_ID)?;
    let verify_time = verify_start.elapsed();

    let journal = stark_receipt.journal.bytes.clone();

    let total_time = total_start.elapsed();

    println!("withdraw setup time: {:?}", setup_time);
    println!("withdraw executor env build time: {:?}", env_time);
    println!("withdraw STARK prove time: {:?}", prove_time);
    println!("withdraw STARK local verify time: {:?}", verify_time);
    println!("withdraw total host time: {:?}", total_time);
    println!();

    println!("withdraw root: {}", hex::encode(root));
    println!("withdraw journal bytes: {}", journal.len());
    println!("withdraw journal hex: {}", hex::encode(&journal));

    decode_withdraw_journal(&journal)?;

    Ok(())
}

fn write_note(builder: &mut ExecutorEnvBuilder<'_>, note: &Note) -> Result<()> {
    builder.write(&note.value)?;
    builder.write_slice(&note.owner_modulus);
    builder.write_slice(&note.nullifier);
    builder.write_slice(&note.secret);

    Ok(())
}

fn random_note(value: u128, owner_modulus: [u8; RSA_MODULUS_BYTES], rng: &mut OsRng) -> Note {
    let mut nullifier = [0u8; NULLIFIER_BYTES];
    let mut secret = [0u8; SECRET_BYTES];

    rng.fill_bytes(&mut nullifier);
    rng.fill_bytes(&mut secret);

    Note {
        value,
        owner_modulus,
        nullifier,
        secret,
    }
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

fn zero_hashes() -> Vec<[u8; 32]> {
    let mut zeros = Vec::with_capacity(DEPTH + 1);

    let mut cur = [0u8; 32];
    zeros.push(cur);

    for level in 0..DEPTH {
        cur = hash_node(level as u32, &cur, &cur);
        zeros.push(cur);
    }

    zeros
}

fn build_sparse_tree(
    indexed_leaves: &[(usize, [u8; 32])],
) -> Result<([u8; 32], Vec<[[u8; 32]; DEPTH]>)> {
    ensure!(!indexed_leaves.is_empty(), "no input leaves");

    let max_leaves = 1usize << DEPTH;
    let zeros = zero_hashes();

    let mut current = BTreeMap::<usize, [u8; 32]>::new();
    let mut positions = Vec::<usize>::with_capacity(indexed_leaves.len());

    for (index, leaf) in indexed_leaves {
        ensure!(*index < max_leaves, "leaf index out of range");
        ensure!(
            current.insert(*index, *leaf).is_none(),
            "duplicate leaf index"
        );

        positions.push(*index);
    }

    let mut paths = vec![[[0u8; 32]; DEPTH]; indexed_leaves.len()];

    for level in 0..DEPTH {
        for i in 0..positions.len() {
            let sibling_index = positions[i] ^ 1;
            paths[i][level] = *current.get(&sibling_index).unwrap_or(&zeros[level]);
        }

        let mut parent_indices = BTreeSet::<usize>::new();

        for index in current.keys() {
            parent_indices.insert(index / 2);
        }

        let mut next = BTreeMap::<usize, [u8; 32]>::new();

        for parent_index in parent_indices {
            let left_index = parent_index * 2;
            let right_index = left_index + 1;

            let left = *current.get(&left_index).unwrap_or(&zeros[level]);
            let right = *current.get(&right_index).unwrap_or(&zeros[level]);

            let parent = hash_node(level as u32, &left, &right);
            next.insert(parent_index, parent);
        }

        current = next;

        for position in positions.iter_mut() {
            *position /= 2;
        }
    }

    let root = *current.get(&0).unwrap_or(&zeros[DEPTH]);

    Ok((root, paths))
}

fn hash_withdraw_action(
    root: &[u8; 32],
    input_leaves: &[[u8; 32]],
    nullifiers: &[[u8; 32]],
    withdraw_amount: u128,
    output_leaf: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();

    h.update(b"stellar-mixer-withdraw-action-v1");
    h.update(root);

    h.update((input_leaves.len() as u32).to_be_bytes());
    for leaf in input_leaves {
        h.update(leaf);
    }

    h.update((nullifiers.len() as u32).to_be_bytes());
    for nullifier in nullifiers {
        h.update(nullifier);
    }

    h.update(withdraw_amount.to_be_bytes());
    h.update(output_leaf);

    h.finalize().into()
}

fn sign_action(
    private_key: &RsaPrivateKey,
    public_key: &RsaPublicKey,
    action_hash: &[u8; 32],
) -> Result<[u8; SIGNATURE_BYTES]> {
    let signing_key = SigningKey::<Sha256>::new(private_key.clone());
    let verifying_key = VerifyingKey::<Sha256>::new(public_key.clone());

    let signature = signing_key.sign(action_hash);
    verifying_key.verify(action_hash, &signature)?;

    fixed_be_array(signature.to_bytes().as_ref())
}

fn fixed_be_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    ensure!(bytes.len() <= N, "integer too large");

    let mut out = [0u8; N];
    let start = N - bytes.len();
    out[start..].copy_from_slice(bytes);

    Ok(out)
}

fn decode_withdraw_journal(journal: &[u8]) -> Result<()> {
    let decoded = WithdrawJournal::decode(&mut &journal[..])?;

    println!();
    println!("Decoded withdraw journal:");
    println!("  root: {}", hex::encode(decoded.root));
    println!("  nullifiers: {}", decoded.nullifiers.len());

    for (i, nullifier) in decoded.nullifiers.iter().enumerate() {
        println!("  nullifier_{}: {}", i, hex::encode(nullifier));
    }

    println!("  withdraw_amount: {}", decoded.withdraw_amount);
    println!("  output_leaf: {}", hex::encode(decoded.output_leaf));

    Ok(())
}

fn image_id_hex_le_words(id: [u32; 8]) -> String {
    let mut out = Vec::with_capacity(32);

    for word in id {
        out.extend_from_slice(&word.to_le_bytes());
    }

    hex::encode(out)
}
