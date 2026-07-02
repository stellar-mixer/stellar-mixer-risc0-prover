use anyhow::Result;
use methods::{TRANSFER_GUEST_ELF, TRANSFER_GUEST_ID, WITHDRAW_GUEST_ELF, WITHDRAW_GUEST_ID};
use std::{fs, path::Path};

fn image_id_hex_le_words(id: [u32; 8]) -> String {
    let mut out = Vec::with_capacity(32);

    for word in id {
        out.extend_from_slice(&word.to_le_bytes());
    }

    hex::encode(out)
}

fn image_id_bytes_le_words(id: [u32; 8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);

    for word in id {
        out.extend_from_slice(&word.to_le_bytes());
    }

    out
}

fn write_artifacts(
    out_dir: &Path,
    name: &str,
    id: [u32; 8],
    elf: &[u8],
) -> Result<()> {
    fs::write(out_dir.join(format!("{name}_image_id_words.txt")), format!("{id:?}\n"))?;
    fs::write(
        out_dir.join(format!("{name}_image_id_hex_le_words.txt")),
        format!("{}\n", image_id_hex_le_words(id)),
    )?;
    fs::write(
        out_dir.join(format!("{name}_image_id.bin")),
        image_id_bytes_le_words(id),
    )?;
    fs::write(out_dir.join(format!("{name}.elf")), elf)?;

    println!("{name}:");
    println!("  image id words: {:?}", id);
    println!("  image id hex le-words: {}", image_id_hex_le_words(id));
    println!("  image id bin: {}", out_dir.join(format!("{name}_image_id.bin")).display());
    println!("  elf: {}", out_dir.join(format!("{name}.elf")).display());
    println!("  elf bytes: {}", elf.len());
    println!();

    Ok(())
}

fn main() -> Result<()> {
    let out_dir = Path::new("artifacts");
    fs::create_dir_all(out_dir)?;

    write_artifacts(out_dir, "transfer_guest", TRANSFER_GUEST_ID, TRANSFER_GUEST_ELF)?;
    write_artifacts(out_dir, "withdraw_guest", WITHDRAW_GUEST_ID, WITHDRAW_GUEST_ELF)?;

    Ok(())
}
