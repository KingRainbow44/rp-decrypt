#![crate_type = "dylib"]

use std::fmt::Debug;
use std::fs::{copy, create_dir_all, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use aes::Aes256;
use aes::cipher::KeyIvInit;
use anyhow::{Context, Result};
use cfb8::cipher::AsyncStreamCipher;
use serde::{Deserialize, Serialize};

/// Utility method to open a file from a path.
fn open_with_context(path: &PathBuf) -> Result<File> {
    File::open(path).with_context(|| format!("Unable to open '{:?}'", path))
}

/// Decrypts the resource pack contents in a directory.
/// Returns true if the resource pack was decrypted successfully.
fn internal_decrypt(
    key: String, // A string of the key, 32 bits.
    pack_dir: String, // Path to the pack directory.
    output_dir: String // Path to the output directory.
) -> Result<bool> {
    let input_path = Path::new(&pack_dir);
    let output_path = Path::new(&output_dir);

    // Create the output path.
    create_dir_all(output_path)?;

    // Copy 'manifest.json' and 'pack_icon.png'.
    for file in &["manifest.json", "pack_icon.png"] {
        copy(input_path.join(file), output_path.join(file))?;
    }

    let content = {
        let key_bytes = key.as_bytes();

        let mut file = open_with_context(&input_path.join("contents.json"))?;
        let mut buffer = Vec::new();
        file.seek(SeekFrom::Start(0x100))?;
        file.read_to_end(&mut buffer)?; // encrypted content list
        Aes256Cfb8Dec::new_from_slices(&key_bytes, &key_bytes[0..16])
            .unwrap()
            .decrypt(&mut buffer);
        serde_json::from_slice::<Content>(&buffer)?
    };

    // copy or decrypt content
    for content_entry in &content.content {
        let input_entry_path = input_path.join(&content_entry.path);
        if !input_entry_path.is_file() {
            continue;
        }

        let output_entry_path = output_path.join(&content_entry.path);
        create_dir_all(output_entry_path.parent().unwrap())?;

        match &content_entry.key {
            None => {
                if input_entry_path != output_entry_path {
                    if content_entry.path.ends_with(".json") {
                        // validate and prettify json
                        match serde_json::from_reader::<_, serde_json::Value>(
                            open_with_context(&input_entry_path)?,
                        ) {
                            Ok(value) => {
                                serde_json::to_writer_pretty(
                                    File::create(output_entry_path)?,
                                    &value,
                                )?;
                            }
                            Err(_) => {
                                copy(input_entry_path, output_entry_path)?;
                            }
                        }
                    } else {
                        copy(input_entry_path, output_entry_path)?;
                    }

                    println!("Copied {}", &content_entry.path);
                }
            }
            Some(key) => {
                let key_bytes = key.as_bytes();

                let mut file = open_with_context(&input_entry_path)?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
                Aes256Cfb8Dec::new_from_slices(key_bytes, &key_bytes[0..16])
                    .unwrap()
                    .decrypt(&mut buffer);
                if content_entry.path.ends_with(".json") {
                    // validate and prettify json
                    match &serde_json::from_slice::<serde_json::Value>(&buffer) {
                        Ok(value) => {
                            serde_json::to_writer_pretty(
                                File::create(output_entry_path)?,
                                &value,
                            )?;
                        }
                        Err(_) => {
                            File::create(output_entry_path)?.write_all(&buffer)?;
                        }
                    }
                } else {
                    File::create(output_entry_path)?.write_all(&buffer)?;
                }
            }
        }
    }

    Ok(true)
}

/// Decrypts the resource pack contents in a directory.
/// Returns true if the resource pack was decrypted successfully.
#[no_mangle]
pub extern fn decrypt(
    key: *const u8, // A string of the key, 32 bits.
    key_len: i32, // Length of the key.
    pack_dir: *const u8, // Path to the pack directory.
    pack_dir_len: i32, // Length of the pack directory.
    output_dir: *const u8, // Path to the output directory.
    output_dir_len: i32 // Length of the output directory.
) -> bool {
    // Convert to strings.
    let key_buffer = unsafe { std::slice::from_raw_parts(key, key_len as usize) };
    let key_str = std::str::from_utf8(key_buffer).unwrap();

    let pack_dir_buffer = unsafe { std::slice::from_raw_parts(pack_dir, pack_dir_len as usize) };
    let pack_dir_str = std::str::from_utf8(pack_dir_buffer).unwrap();

    let output_dir_buffer = unsafe { std::slice::from_raw_parts(output_dir, output_dir_len as usize) };
    let output_dir_str = std::str::from_utf8(output_dir_buffer).unwrap();

    // Attempt to decrypt the resource pack.
    let result = internal_decrypt(
        key_str.to_string(),
        pack_dir_str.to_string(),
        output_dir_str.to_string());

    match result {
        Ok(_) => true,
        Err(_error) => {
            println!("Error: {:?}", _error);
            false
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Manifest {
    header: ManifestHeader,
}

#[derive(Serialize, Deserialize, Debug)]
struct ManifestHeader {
    uuid: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Content {
    // version: u32,
    content: Vec<ContentEntry>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ContentEntry {
    path: String,
    key: Option<String>,
}

type Aes256Cfb8Dec = cfb8::Decryptor<Aes256>;