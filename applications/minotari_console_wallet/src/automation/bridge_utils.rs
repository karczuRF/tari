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
use tari_common_types::types::{PrivateKey, PublicKey};
use tari_core::transactions::transaction_components::{TransactionKernel, TransactionOutput};
use tari_crypto::{hasher, keys::SecretKey};
use tari_utilities::{encoding::Base58, ByteArray};

use super::{
    bridge::{BridgeItem, CreateBridgeUtxoScriptInputsForLeader},
    commands::{FILE_EXTENSION, STEP_1_FAIL_SAFE_LEADER, STEP_1_LEADER},
    error::CommandError,
};

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

pub fn read_inputs_from_party_members(
    file_path: &Path,
) -> Result<(Vec<PathBuf>, Vec<Vec<CreateBridgeUtxoScriptInputsForLeader>>), String> {
    let mut party_files = Vec::new();
    let mut threshold_inputs = Vec::new();
    match fs::read_dir(file_path) {
        Ok(entries) => {
            for file in entries.flatten() {
                if let Some(file_name) = file.path().file_name() {
                    if let Some(val) = file_name.to_str() {
                        if (val.starts_with(STEP_1_LEADER) || val.starts_with(STEP_1_FAIL_SAFE_LEADER))
                            && val.ends_with(FILE_EXTENSION)
                        {
                            let party_info = match json_from_file_single_object::<
                                _,
                                Vec<CreateBridgeUtxoScriptInputsForLeader>,
                            >(file.path(), None)
                            {
                                Ok(info) => info,
                                Err(e) => return Err(format!("{}", e)),
                            };
                            threshold_inputs.push(party_info);
                            party_files.push(file.path());
                        }
                    }
                }
            }
        },
        Err(e) => return Err(format!("{}", e)),
    }
    Ok((party_files, threshold_inputs))
}

pub fn get_fail_safe_wallet(
    threshold_inputs: &mut Vec<Vec<CreateBridgeUtxoScriptInputsForLeader>>,
    party_files: &mut Vec<PathBuf>,
) -> Result<(PathBuf, Vec<CreateBridgeUtxoScriptInputsForLeader>), String> {
    if threshold_inputs.len() != party_files.len() {
        return Err("Error: Threshold inputs and party files have different lengths!".to_string());
    }

    let mut fail_safe_wallet_index = None;
    for (i, item) in threshold_inputs.iter().enumerate() {
        if let Some(pre_mine_entry) = item.first() {
            if threshold_inputs.len() != pre_mine_entry.multi_sig_count as usize + 1 {
                return Err(format!(
                    "Error: Incorrect number of party files, expected {}, received {}!",
                    pre_mine_entry.multi_sig_count as usize + 1,
                    threshold_inputs.len(),
                ));
            }
            let challenge = match get_proof_signature_challenge(true, 0, pre_mine_entry.multi_sig_count) {
                Ok(val) => val,
                Err(e) => {
                    return Err(format!(
                        "Error: Could not create signature challenge for output 0: {}",
                        e
                    ));
                },
            };
            if pre_mine_entry
                .verification_signature
                .verify(&pre_mine_entry.script_public_key, challenge.as_bytes())
            {
                if fail_safe_wallet_index.is_some() {
                    return Err("Error: Multiple fail-safe wallets found!".to_string());
                }
                fail_safe_wallet_index = Some(i);
            }
        } else {
            return Err(format!("Error: Empty input file '{}'", party_files[i].display()));
        }
    }

    if let Some(index) = fail_safe_wallet_index {
        let backup_inputs = threshold_inputs.remove(index);
        let fail_safe_file = party_files.remove(index);
        Ok((fail_safe_file, backup_inputs))
    } else {
        Err("Error: No fail-safe wallet found!".to_string())
    }
}

pub fn verify_script_bridge_inputs(
    threshold_inputs: &[Vec<CreateBridgeUtxoScriptInputsForLeader>],
    backup_inputs: &[CreateBridgeUtxoScriptInputsForLeader],
    party_file_names: &[PathBuf],
    fail_safe_file_name: &Path,
    bridge_items: &[BridgeItem],
    network: Network,
) -> Result<(), String> {
    for (k, party_info) in threshold_inputs.iter().enumerate() {
        verify_party_script_inputs(&party_file_names[k], party_info, bridge_items, network, false)?;
    }
    verify_party_script_inputs(fail_safe_file_name, backup_inputs, bridge_items, network, true)?;

    // Ensure no keys for the same index are duplicated
    let (_threshold_spend_keys, _backup_spend_keys, mut all_spend_keys) =
        extract_threshold_and_backup_spend_keys(threshold_inputs, backup_inputs)?;
    for (i, keys) in all_spend_keys.iter_mut().enumerate() {
        let keys_len = keys.len();
        keys.sort();
        keys.dedup();
        if keys.len() != keys_len {
            return Err(format!("Duplicate script keys for index '{}'!", i));
        }
    }
    // Ensure no keys for any index are duplicated
    let mut all_spend_keys_flattened = all_spend_keys.into_iter().flatten().collect::<Vec<_>>();
    all_spend_keys_flattened.sort();
    let all_spend_keys_len = all_spend_keys_flattened.len();
    all_spend_keys_flattened.dedup();
    if all_spend_keys_flattened.len() != all_spend_keys_len {
        return Err("Duplicate script keys across parties!".to_string());
    }

    Ok(())
}

fn verify_party_script_inputs(
    party_file_name: &Path,
    party_info: &[CreateBridgeUtxoScriptInputsForLeader],
    bridge_items: &[BridgeItem],
    network: Network,
    fail_safe_wallet: bool,
) -> Result<(), String> {
    if party_info.len() != bridge_items.len() {
        return Err(format!(
            "Number of items in '{}' does not match the pre-mine items!",
            party_file_name.display()
        ));
    }
    // Ensure each key is unique
    let mut script_keys = party_info
        .iter()
        .map(|v| v.script_public_key.clone())
        .collect::<Vec<_>>();
    script_keys.sort();
    script_keys.dedup();
    if script_keys.len() != bridge_items.len() {
        return Err(format!("Duplicate script keys in '{}'!", party_file_name.display()));
    }
    // Verify knowledge of the script private key
    for (index, item) in party_info.iter().enumerate() {
        let challenge = match get_proof_signature_challenge(fail_safe_wallet, index as u64, item.multi_sig_count) {
            Ok(val) => val,
            Err(e) => {
                return Err(format!(
                    "Error: Could not create signature challenge for output 0: {}",
                    e
                ));
            },
        };
        if !item
            .verification_signature
            .verify(&item.script_public_key, challenge.as_bytes())
        {
            return Err(format!(
                "Verification signature at index {} in '{}' is not valid!",
                index,
                party_file_name.display()
            ));
        }
        if item.index != index as u64 {
            return Err(format!(
                "Index {} in '{}' does not align!",
                index,
                party_file_name.display()
            ));
        }
        if item.network != network {
            return Err(format!(
                "Network '{}' in '{}' does not align with the current network!",
                item.network,
                party_file_name.display()
            ));
        }
    }
    Ok(())
}

type PublicKeyVec = Vec<PublicKey>;

pub fn extract_threshold_and_backup_spend_keys(
    threshold_inputs: &[Vec<CreateBridgeUtxoScriptInputsForLeader>],
    backup_inputs: &[CreateBridgeUtxoScriptInputsForLeader],
) -> Result<(Vec<PublicKeyVec>, PublicKeyVec, Vec<PublicKeyVec>), String> {
    for item in threshold_inputs {
        if item.is_empty() || item.len() != backup_inputs.len() {
            return Err("Threshold/backup inputs empty or have different lengths!".to_string());
        }
    }
    let mut threshold_spend_keys = Vec::with_capacity(threshold_inputs[0].len());
    let mut backup_spend_keys = Vec::with_capacity(threshold_inputs[0].len());
    let mut all_spend_keys = Vec::with_capacity(threshold_inputs[0].len());
    for i in 0..threshold_inputs[0].len() {
        let mut keys_for_round = Vec::with_capacity(threshold_inputs.len());
        for party_info in threshold_inputs {
            keys_for_round.push(party_info[i].script_public_key.clone());
        }
        threshold_spend_keys.push(keys_for_round.clone());
        backup_spend_keys.push(backup_inputs[i].clone().script_public_key);
        keys_for_round.push(backup_inputs[i].clone().script_public_key);
        all_spend_keys.push(keys_for_round);
    }
    Ok((threshold_spend_keys, backup_spend_keys, all_spend_keys))
}

/// Create a unique session-based output directory
pub(crate) fn create_multisig_utxo_output_dir(
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
