// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! # Application utilities

use std::{
    fs,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    iter,
    path::{Path, PathBuf},
};

use blake2::{digest::consts::U64, Blake2b};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use serde::{de::DeserializeOwned, Serialize};
use tari_common::configuration::Network;
use tari_common_types::types::PrivateKey;
use tari_core::transactions::transaction_components::{TransactionKernel, TransactionOutput};
use tari_crypto::{hasher, keys::SecretKey};
use tari_utilities::{encoding::Base58, ByteArray};

use super::{commands::FILE_EXTENSION, error::CommandError};

/// Set terminal/console title on non-Windows systems
#[cfg(not(target_os = "windows"))]
pub(crate) fn set_console_title(title: &str) {
    use std::io::{self, Write};

    let mut stdout = io::stdout().lock();
    let _unused = write!(stdout, "\x1b]0;{}\x07", title);
}
/// Set terminal/console title on Windows systems
#[cfg(target_os = "windows")]
pub(crate) fn set_console_title(title: &str) {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt};

    use winapi::um::wincon::SetConsoleTitleW;

    let wide_title: Vec<u16> = OsStr::new(title).encode_wide().chain(Some(0)).collect();
    unsafe { SetConsoleTitleW(wide_title.as_ptr()) };
}

/// Create a unique session-based output directory
pub(crate) fn create_pre_mine_output_dir_with_network(
    alias: Option<&str>,
    network: Option<Network>,
) -> Result<(String, PathBuf), CommandError> {
    let mut session_id = PrivateKey::random(&mut OsRng).to_base58();
    session_id.truncate(10);
    if let Some(alias) = alias {
        session_id.push('_');
        session_id.push_str(alias);
    }
    if let Some(network) = network {
        session_id.push_str(&format!("_{}", network));
    }
    let out_dir = out_dir(&session_id)?;
    fs::create_dir_all(out_dir.clone())
        .map_err(|e| CommandError::JsonFile(format!("{} ({})", e, out_dir.display())))?;
    Ok((session_id, out_dir))
}

/// Return the output directory for the session
pub(crate) fn out_dir(session_id: &str) -> Result<PathBuf, CommandError> {
    let base_dir = dirs_next::document_dir().ok_or(CommandError::InvalidArgument(
        "Could not find cache directory".to_string(),
    ))?;
    Ok(base_dir.join("tari_pre_mine").join("create").join(session_id))
}

// TODO reduntant get_file_name
/// Create the file name with the given stem and optional suffix & network
pub(crate) fn get_file_name_with_network(stem: &str, suffix: Option<String>, network: Option<Network>) -> String {
    let mut file_name = stem.to_string();
    if let Some(suffix) = suffix {
        file_name.push_str(&suffix);
    }
    if let Some(network) = network {
        file_name.push_str(&format!("_{}", network));
    }
    file_name.push('.');
    file_name.push_str(FILE_EXTENSION);
    file_name
}

/// Write outputs to a JSON file
pub(crate) fn write_to_json_file<T: Serialize>(file: &Path, reset_file: bool, data: T) -> Result<(), CommandError> {
    if let Some(file_path) = file.parent() {
        if !file_path.exists() {
            fs::create_dir_all(file_path).map_err(|e| CommandError::JsonFile(format!("{} ({})", e, file.display())))?;
        }
    }
    if reset_file && file.exists() {
        fs::remove_file(file).map_err(|e| CommandError::JsonFile(e.to_string()))?;
    }
    append_to_json_file(file, data)?;
    Ok(())
}

fn append_to_json_file<P: AsRef<Path>, T: Serialize>(file: P, data: T) -> Result<(), CommandError> {
    fs::create_dir_all(file.as_ref().parent().unwrap()).map_err(|e| CommandError::JsonFile(e.to_string()))?;
    let mut file_object = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file)
        .map_err(|e| CommandError::JsonFile(e.to_string()))?;
    let json = serde_json::to_string_pretty(&data).map_err(|e| CommandError::JsonFile(e.to_string()))?;
    writeln!(file_object, "{json}").map_err(|e| CommandError::JsonFile(e.to_string()))?;
    Ok(())
}

//. Instructions to read the JSON file
#[derive(Debug)]
pub(crate) struct PartialRead {
    pub(crate) lines_to_read: usize,
    pub(crate) lines_to_skip: usize,
}

/// Reads an entire file into a single JSON object
pub(crate) fn json_from_file_single_object<P: AsRef<Path>, T: DeserializeOwned>(
    path: P,
    partial_read: Option<PartialRead>,
) -> Result<T, CommandError> {
    if let Some(val) = partial_read {
        let lines = BufReader::new(
            File::open(path.as_ref())
                .map_err(|e| CommandError::JsonFile(format!("{e} '{}'", path.as_ref().display())))?,
        )
        .lines()
        .take(val.lines_to_read)
        .skip(val.lines_to_skip);
        let mut json_str = String::new();
        for line in lines {
            let line = line.map_err(|e| CommandError::JsonFile(format!("{e} '{}'", path.as_ref().display())))?;
            json_str.push_str(&line);
        }
        serde_json::from_str(&json_str)
            .map_err(|e| CommandError::JsonFile(format!("{e} '{}'", path.as_ref().display())))
    } else {
        serde_json::from_reader(BufReader::new(
            File::open(path.as_ref())
                .map_err(|e| CommandError::JsonFile(format!("{e} '{}'", path.as_ref().display())))?,
        ))
        .map_err(|e| CommandError::JsonFile(format!("{e} '{}'", path.as_ref().display())))
    }
}

/// Returns a random string of the given length
pub(crate) fn random_string(len: usize) -> String {
    iter::repeat(())
        .map(|_| OsRng.sample(Alphanumeric) as char)
        .take(len)
        .collect()
}

hasher!(Blake2b<U64>, PreMineHasher, "tari.pre-min-creation", 1, pre_mine_hasher);

pub(crate) fn get_proof_signature_challenge(
    fail_safe_wallet: bool,
    index: u64,
    multi_sig_count: u8,
) -> Result<PrivateKey, CommandError> {
    let hash = PreMineHasher::new_with_label("stealth_address")
        .chain(u8::from(fail_safe_wallet).to_le_bytes().as_bytes())
        .chain(index.to_le_bytes().as_bytes())
        .chain(multi_sig_count.to_le_bytes().as_bytes())
        .finalize();

    Ok(PrivateKey::from_uniform_bytes(hash.as_ref())?)
}

pub fn get_bridge_utxo_file_name() -> String {
    match Network::get_current_or_user_setting_or_default() {
        Network::MainNet => "mainnet_bridg_utxo.json".to_string(),
        Network::StageNet => "stagenet_bridg_utxo.json".to_string(),
        Network::NextNet => "nextnet_bridg_utxo.json".to_string(),
        Network::LocalNet => "esmeralda_bridg_utxo.json".to_string(),
        Network::Igor => "igor_bridg_utxo.json".to_string(),
        Network::Esmeralda => "esmeralda_bridg_utxo.json".to_string(),
    }
}

/// Read the genesis file and return transaction outputs and the kernel
pub(crate) fn read_genesis_file(file_path: &Path) -> Result<(Vec<TransactionOutput>, TransactionKernel), CommandError> {
    let file = File::open(file_path)
        .map_err(|e| CommandError::PreMine(format!("Problem opening file '{}' ({})", file_path.display(), e)))?;
    let reader = BufReader::new(file);

    let mut outputs = Vec::new();
    let mut kernel: Option<TransactionKernel> = None;

    for line in reader.lines() {
        let line = line.map_err(|e| {
            CommandError::PreMine(format!(
                "Problem reading line in file '{}' ({})",
                file_path.display(),
                e
            ))
        })?;
        if let Ok(output) = serde_json::from_str::<TransactionOutput>(&line) {
            outputs.push(output);
        } else if let Ok(k) = serde_json::from_str::<TransactionKernel>(&line) {
            kernel = Some(k);
        } else {
            eprintln!("Error: Could not deserialize line: {}", line);
        }
    }
    if outputs.is_empty() {
        return Err(CommandError::PreMine(format!(
            "No outputs found in '{}'",
            file_path.display()
        )));
    }
    let kernel =
        kernel.ok_or_else(|| CommandError::PreMine(format!("No kernel found in '{}'", file_path.display())))?;

    Ok((outputs, kernel))
}
