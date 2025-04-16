use std::convert::{TryFrom, TryInto};
use std::{iter, mem::size_of, sync::Arc};

use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng, RngCore};
use tari_common::configuration::Network;
use tari_common_sqlite::connection::{DbConnection, DbConnectionUrl};
use tari_common_types::types::{CompressedCommitment, CompressedPublicKey};
use tari_common_types::wallet_types::WalletType;
use tari_comms::types::Signature;
use tari_core::transactions::transaction_key_manager::create_memory_db_key_manager_with_range_proof_size;
use tari_crypto::compressed_key::CompressedKey;
use tari_crypto::ristretto::RistrettoPublicKey;
use tari_crypto::signatures::CompressedSchnorrSignature;
use tari_key_manager::cipher_seed::CipherSeed;
use zeroize::Zeroizing;

use tari_core::{
    one_sided::public_key_to_output_encryption_key,
    transactions::{
        tari_amount::MicroMinotari,
        transaction_components::{
            encrypted_data::PaymentId, CoinBaseExtra, KernelFeatures, OutputFeatures, OutputFeaturesVersion,
            OutputType, RangeProofType, TransactionKernel, TransactionKernelVersion, TransactionOutput,
            TransactionOutputVersion, WalletOutputBuilder,
        },
        transaction_key_manager::{
            error::KeyManagerServiceError,
            storage::{database::TransactionKeyManagerDatabase, sqlite_db::TransactionKeyManagerSqliteDatabase},
            SecretTransactionKeyManagerInterface, TransactionKeyManagerInterface, TransactionKeyManagerWrapper,
        },
        transaction_protocol::TransactionMetadata,
        CryptoFactories,
    },
};
pub type MemoryDbKeyManager = TransactionKeyManagerWrapper<TransactionKeyManagerSqliteDatabase<DbConnection>>;

use rand::{prelude::SliceRandom, thread_rng};
use tari_common_types::{
    key_branches::TransactionKeyManagerBranch,
    types::{PrivateKey, PublicKey},
};

use serde::{Deserialize, Serialize};
use tari_crypto::keys::{PublicKey as PkTrait, SecretKey as SkTrait};
use tari_script::{script, CheckSigSchnorrSignature, ExecutionStack};
use tari_utilities::ByteArray;

/// Pre-mine values
#[derive(Debug)]
pub struct BridgeItem {
    /// The value of the pre-mine
    pub value: MicroMinotari,
    /// The maturity of the pre-mine at which it can be spend
    pub maturity: u64,
    /// The destination address
    pub destination_address: String,
    /// The fail-safe height (absolute height) at which the pre-mine can be spent by a backup or fail-safe wallet
    pub fail_safe_height: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateBridgeUtxoScriptInputsForLeader {
    pub index: u64,
    pub script_public_key: PublicKey,
    pub verification_signature: CheckSigSchnorrSignature,
    pub network: Network,
    pub multi_sig_count: u8,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateBridgeUtxoScriptInputsForSelf {
    pub account: u64,
    pub network: Network,
    pub multi_sig_count: u8,
}

fn random_string(len: usize) -> String {
    iter::repeat(())
        .map(|_| OsRng.sample(Alphanumeric) as char)
        .take(len)
        .collect()
}

pub fn create_memory_db_key_manager(
    wallet_type: Arc<WalletType>,
) -> Result<MemoryDbKeyManager, KeyManagerServiceError> {
    let connection = DbConnection::connect_url(&DbConnectionUrl::MemoryShared(random_string(8)))?;
    let cipher = CipherSeed::new();

    let mut key = Zeroizing::new([0u8; size_of::<Key>()]);
    OsRng.fill_bytes(key.as_mut());
    let key_ga = Key::from_slice(key.as_ref());
    let db_cipher = XChaCha20Poly1305::new(key_ga);
    let factory = CryptoFactories::new(64);
    TransactionKeyManagerWrapper::<TransactionKeyManagerSqliteDatabase<DbConnection>>::new(
        cipher,
        TransactionKeyManagerDatabase::new(TransactionKeyManagerSqliteDatabase::init(connection, db_cipher)),
        factory,
        wallet_type,
    )
}

// TODO dupa
/// Create pre-mine genesis block info with the given pre-mine items and party public keys
pub async fn create_utxo_bridge_info(
    bridge_item: &[BridgeItem],
    threshold_spend_keys: &[Vec<PublicKey>],
    backup_spend_keys: &[PublicKey],
) -> Result<(Vec<TransactionOutput>, TransactionKernel), String> {
    let mut outputs = Vec::new();
    let mut total_private_key = PrivateKey::default();
    for (i, ((item, public_keys), backup_key)) in bridge_item
        .iter()
        .zip(threshold_spend_keys)
        .zip(backup_spend_keys)
        .enumerate()
    {
        let signature_threshold = get_signature_threshold(public_keys.len())?;

        // TODO verify if this makes sense
        let compressed_public_keys: Vec<CompressedKey<RistrettoPublicKey>> = public_keys
            .iter()
            .map(|item| CompressedKey::new_from_pk((*item).clone()))
            .collect();
        let total_script_key = public_keys.iter().fold(PublicKey::default(), |acc, x| acc + x);
        let compressed_total_script_key = CompressedKey::new_from_pk(total_script_key);

        let key_manager = create_memory_db_key_manager_with_range_proof_size(64).unwrap();
        let view_key = public_key_to_output_encryption_key(&compressed_total_script_key).unwrap();
        let view_key_id = key_manager.import_key(view_key.clone()).await.unwrap();
        let address_len = u8::try_from(public_keys.len()).unwrap();

        let (commitment_mask, script_key) = key_manager.get_next_commitment_mask_and_script_key().await.unwrap();
        total_private_key = total_private_key + &key_manager.get_private_key(&commitment_mask.key_id).await.unwrap();
        let commitment = key_manager
            .get_commitment(&commitment_mask.key_id, &item.value.into())
            .await
            .unwrap();
        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.clone_from_slice(commitment.as_bytes());

        let sender_offset = key_manager
            .get_next_key(TransactionKeyManagerBranch::SenderOffset.get_branch_key())
            .await
            .unwrap();
        let mut compressed_public_keys = compressed_public_keys.clone();
        compressed_public_keys.shuffle(&mut thread_rng());

        // verify if this makes sense to create compressed
        let compressed_backup = CompressedKey::new_from_pk((*backup_key).clone());
        let script = script!(
            CheckHeight(item.fail_safe_height) LeZero
            IfThen
            CheckMultiSigVerifyAggregatePubKey(signature_threshold, address_len, compressed_public_keys.clone(), Box::new(commitment_bytes))
            Else
            PushPubKey(Box::new(compressed_backup.clone()))
            EndIf
        ).map_err(|e| e.to_string())?;
        let output = WalletOutputBuilder::new(item.value, commitment_mask.key_id)
            .with_features(OutputFeatures::new(
                OutputFeaturesVersion::get_current_version(),
                OutputType::Standard,
                0,
                CoinBaseExtra::default(),
                None,
                RangeProofType::RevealedValue,
            ))
            .with_script(script)
            .encrypt_data_for_recovery(&key_manager, Some(&view_key_id), PaymentId::U64(i.try_into().unwrap()))
            .await
            .unwrap()
            .with_input_data(ExecutionStack::default())
            .with_version(TransactionOutputVersion::get_current_version())
            .with_sender_offset_public_key(sender_offset.pub_key)
            .with_script_key(script_key.key_id)
            .with_minimum_value_promise(item.value)
            .sign_as_sender_and_receiver(&key_manager, &sender_offset.key_id)
            .await
            .unwrap()
            .try_build(&key_manager)
            .await
            .unwrap();
        outputs.push(output.to_transaction_output(&key_manager).await.unwrap());
    }
    // lets create a single kernel for all the outputs
    let r = PrivateKey::random(&mut OsRng);
    let tx_meta = TransactionMetadata::new_with_features(0.into(), 0, KernelFeatures::empty());
    let total_public_key = CompressedPublicKey::from_secret_key(&total_private_key);
    let e = TransactionKernel::build_kernel_challenge_from_tx_meta(
        &TransactionKernelVersion::get_current_version(),
        &CompressedPublicKey::from_secret_key(&r),
        &total_public_key,
        &tx_meta,
    );

    //TODO double check if types and arg are correct
    let signature = Signature::sign_raw_uniform(&total_private_key, r, &e).unwrap();
    let compressed_signature = CompressedSchnorrSignature::new_from_schnorr(signature);
    let excess = CompressedCommitment::from_public_key(total_public_key.to_public_key().unwrap());
    let kernel = TransactionKernel::new_current_version(
        KernelFeatures::empty(),
        0.into(),
        0,
        excess,
        compressed_signature,
        None,
    );
    Ok((outputs, kernel))
}

// The threshold is 1 more than half of the public keys if even, otherwise 1 more than half of 'public keys - 1'
fn get_signature_threshold(number_of_keys: usize) -> Result<u8, String> {
    if number_of_keys < 2 {
        return Err("Invalid number of parties, must be > 1".to_string());
    }
    u8::try_from(number_of_keys / 2 + 1).map_err(|e| e.to_string())
}
