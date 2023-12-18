use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_error::Error;
use ckb_script::{TransactionScriptsVerifier, TxVerifyEnv};
use ckb_traits::{CellDataProvider, ExtensionProvider, HeaderProvider};
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    core::{
        cell::{CellMeta, CellMetaBuilder, ResolvedTransaction},
        Capacity, DepType, HeaderView, ScriptHashType, TransactionBuilder, TransactionView,
    },
    packed::{
        self, Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs,
        WitnessArgsBuilder,
    },
    prelude::*,
    H256,
};
use log::{Metadata, Record};
use rand::{distributions::Standard, thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::TryInto, mem::size_of, vec};

use ckb_auth_rs::{AuthAlgorithmIdType, CkbAuthType};
use std::sync::Arc;

pub mod test_config;
use test_config::*;

pub mod on_chain_script;
use on_chain_script::*;

pub mod auth;
pub use auth::*;

mod tests;

pub const MAX_CYCLES: u64 = std::u64::MAX;
pub const SIGNATURE_SIZE: usize = 65;
pub const RNG_SEED: u64 = 42;

fn _dbg_print_mem(data: &Vec<u8>, name: &str) {
    print!("rustdbg {}: (size:{})\n", name, data.len());
    let mut count = 0;
    for i in data {
        print!("0x{:02X}, ", i);
        if count % 8 == 7 {
            print!("\n");
        }
        count += 1;
    }
    print!("\n");
}

pub fn calculate_sha256(buf: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut c = Sha256::new();
    c.update(buf);
    c.finalize().into()
}

pub fn calculate_ripemd160(buf: &[u8]) -> [u8; 20] {
    use ripemd::{Digest, Ripemd160};

    let mut hasher = Ripemd160::new();
    hasher.update(buf);
    let buf = hasher.finalize()[..].to_vec();

    buf.try_into().unwrap()
}

#[derive(Default, Clone)]
pub struct DummyDataLoader {
    pub cells: HashMap<OutPoint, (CellOutput, ckb_types::bytes::Bytes)>,
}

impl DummyDataLoader {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CellDataProvider for DummyDataLoader {
    // load Cell Data
    fn load_cell_data(&self, cell: &CellMeta) -> Option<ckb_types::bytes::Bytes> {
        cell.mem_cell_data.clone().or_else(|| {
            self.cells
                .get(&cell.out_point)
                .map(|(_, data)| data.clone())
        })
    }

    fn load_cell_data_hash(&self, cell: &CellMeta) -> Option<Byte32> {
        self.load_cell_data(cell)
            .map(|e| CellOutput::calc_data_hash(&e))
    }

    fn get_cell_data(&self, _out_point: &OutPoint) -> Option<ckb_types::bytes::Bytes> {
        None
    }

    fn get_cell_data_hash(&self, _out_point: &OutPoint) -> Option<Byte32> {
        None
    }
}

impl HeaderProvider for DummyDataLoader {
    fn get_header(&self, _hash: &Byte32) -> Option<HeaderView> {
        None
    }
}

impl ExtensionProvider for DummyDataLoader {
    fn get_block_extension(&self, _hash: &packed::Byte32) -> Option<packed::Bytes> {
        None
    }
}

pub fn sign_tx(tx: TransactionView, config: &TestConfig) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    sign_tx_by_input_group(tx, config, 0, witnesses_len)
}

pub fn get_message_to_sign(tx: TransactionView, config: &TestConfig) -> H256 {
    let witnesses_len = tx.witnesses().len();
    get_message_to_sign_by_input_group(tx, config, 0, witnesses_len)
}

pub fn get_message_to_sign_by_input_group(
    tx: TransactionView,
    config: &TestConfig,
    begin_index: usize,
    len: usize,
) -> H256 {
    let tx_hash = tx.hash();
    tx.inputs()
        .into_iter()
        .enumerate()
        .find_map(|(i, _)| {
            if i == begin_index {
                let mut blake2b = ckb_hash::new_blake2b();
                let mut message = [0u8; 32];
                blake2b.update(&tx_hash.raw_data());
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(config.auth.get_sign_size(), 0);
                    buf.into()
                };
                let witness_for_digest = witness
                    .clone()
                    .as_builder()
                    .lock(Some(zero_lock).pack())
                    .build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                blake2b.update(&witness_len.to_le_bytes());
                blake2b.update(&witness_for_digest.as_bytes());
                ((i + 1)..(i + len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    blake2b.update(&witness_len.to_le_bytes());
                    blake2b.update(&witness.raw_data());
                });
                blake2b.finalize(&mut message);
                Some(config.auth.convert_message(&message))
            } else {
                None
            }
        })
        .unwrap()
}

pub fn set_signature(tx: TransactionView, signature: &Bytes) -> TransactionView {
    set_signature_by_index(tx, signature, 0)
}

pub fn set_signature_by_index(
    tx: TransactionView,
    signature: &Bytes,
    begin_index: usize,
) -> TransactionView {
    // We need to pass to ownership of signature to the closure in map below.
    let mut signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == begin_index {
                let witness =
                    WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap_or_default().unpack());
                witness
                    .as_builder()
                    .lock(Some(signature.clone()).pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap_or_default()
            }
        })
        .collect();
    for i in signed_witnesses.len()..tx.witnesses().len() {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

pub fn sign_tx_by_input_group(
    tx: TransactionView,
    config: &TestConfig,
    begin_index: usize,
    len: usize,
) -> TransactionView {
    let mut rng = thread_rng();
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == begin_index {
                let mut blake2b = ckb_hash::new_blake2b();
                let mut message = [0u8; 32];
                blake2b.update(&tx_hash.raw_data());
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(config.auth.get_sign_size(), 0);
                    buf.into()
                };
                let witness_for_digest = witness
                    .clone()
                    .as_builder()
                    .lock(Some(zero_lock).pack())
                    .build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                blake2b.update(&witness_len.to_le_bytes());
                blake2b.update(&witness_for_digest.as_bytes());
                ((i + 1)..(i + len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    blake2b.update(&witness_len.to_le_bytes());
                    blake2b.update(&witness.raw_data());
                });
                blake2b.finalize(&mut message);
                if config.incorrect_msg {
                    rng.fill(&mut message);
                }
                let sig;
                if config.incorrect_sign {
                    sig = {
                        let buff: Vec<u8> = rng.sample_iter(&Standard).take(16).collect();
                        Bytes::from(buff)
                    };
                } else {
                    sig = config.auth.sign(&config.auth.convert_message(&message));
                }

                let sig2 = match config.incorrect_sign_size {
                    TestConfigIncorrectSing::None => sig,
                    TestConfigIncorrectSing::Bigger => {
                        let sign_size = rng.gen_range(1, 64);
                        let mut buff = BytesMut::with_capacity(sig.len() + sign_size);
                        buff.put(sig);
                        let mut fillbuffer: BytesMut = BytesMut::with_capacity(sign_size);
                        for _i in 0..(sign_size - 1) {
                            fillbuffer.put_u8(rng.gen_range(0, 255) as u8);
                        }
                        buff.put(Bytes::from(fillbuffer));
                        buff.freeze()
                    }
                    TestConfigIncorrectSing::Smaller => {
                        let sign_size = rng.gen_range(1, sig.len() - 8);
                        let temp_sig = &sig.to_vec()[0..sign_size];
                        Bytes::from(temp_sig.to_vec())
                    }
                };

                witness
                    .as_builder()
                    .lock(Some(sig2).pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap_or_default()
            }
        })
        .collect();
    for i in signed_witnesses.len()..tx.witnesses().len() {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

fn append_cell_deps<R: Rng>(
    dummy: &mut DummyDataLoader,
    rng: &mut R,
    deps_data: &Bytes,
) -> OutPoint {
    // setup sighash_all dep
    let sighash_all_out_point = {
        let contract_tx_hash = {
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            buf.pack()
        };
        OutPoint::new(contract_tx_hash, 0)
    };

    // dep contract code
    let sighash_all_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(deps_data.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    dummy.cells.insert(
        sighash_all_out_point.clone(),
        (sighash_all_cell, deps_data.clone()),
    );

    sighash_all_out_point
}

fn append_cells_deps<R: Rng>(
    dummy: &mut DummyDataLoader,
    config: &TestConfig,
    rng: &mut R,
) -> (Capacity, TransactionBuilder) {
    // setup default tx builder
    let dummy_capacity = Capacity::shannons(42);
    let tx_builder = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(append_cell_deps(
                    dummy,
                    rng,
                    config.auth_lock_type.get_bin(),
                ))
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(append_cell_deps(dummy, rng, &ALWAYS_SUCCESS))
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(append_cell_deps(dummy, rng, &SECP256K1_DATA_BIN))
                .dep_type(DepType::Code.into())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .build(),
        )
        .output_data(Bytes::new().pack());

    let tx_builder = if config.load_all_auth {
        tx_builder
            .cell_dep(
                CellDep::new_builder()
                    .out_point(append_cell_deps(
                        dummy,
                        rng,
                        &on_chain_script::ORIGINAL_AUTH_PROGRAM,
                    ))
                    .dep_type(DepType::Code.into())
                    .build(),
            )
            .cell_dep(
                CellDep::new_builder()
                    .out_point(append_cell_deps(
                        dummy,
                        rng,
                        &on_chain_script::LIBECC_AUTH_PROGRAM,
                    ))
                    .dep_type(DepType::Code.into())
                    .build(),
            )
    } else {
        tx_builder.cell_dep(
            CellDep::new_builder()
                .out_point(append_cell_deps(
                    dummy,
                    rng,
                    config.auth_script_type.get_bin(),
                ))
                .dep_type(DepType::Code.into())
                .build(),
        )
    };

    (dummy_capacity, tx_builder)
}

pub fn gen_tx_with_pub_key_hash(
    dummy: &mut DummyDataLoader,
    config: &TestConfig,
    hash: Vec<u8>,
) -> TransactionView {
    let lock_args = gen_args_with_pub_key_hash(&config, hash);
    // Note that we use deterministic here to ensure the same transaction structure
    // is generated.
    let mut rng: rand::rngs::SmallRng = rand::SeedableRng::seed_from_u64(RNG_SEED);

    gen_tx_with_grouped_args(
        dummy,
        vec![(lock_args, config.inputs_size as usize)],
        config,
        &mut rng,
    )
}

pub fn gen_tx(dummy: &mut DummyDataLoader, config: &TestConfig) -> TransactionView {
    let lock_args = gen_args(&config);

    let mut rng = thread_rng();
    gen_tx_with_grouped_args(
        dummy,
        vec![(lock_args, config.inputs_size as usize)],
        config,
        &mut rng,
    )
}

pub fn gen_tx_with_grouped_args<R: Rng>(
    dummy: &mut DummyDataLoader,
    grouped_args: Vec<(Bytes, usize)>,
    config: &TestConfig,
    rng: &mut R,
) -> TransactionView {
    let (dummy_capacity, mut tx_builder) = append_cells_deps(dummy, config, rng);

    let sighash_all_cell_data_hash = CellOutput::calc_data_hash(config.auth_lock_type.get_bin());

    let sighash_all_cell_hash_type = ScriptHashType::Data2;

    for (args, inputs_size) in grouped_args {
        // setup dummy input unlock script
        for _ in 0..inputs_size {
            let previous_tx_hash = {
                let mut buf = [0u8; 32];
                rng.fill(&mut buf);
                buf.pack()
            };
            let previous_out_point = OutPoint::new(previous_tx_hash, 0);
            let script = Script::new_builder()
                .args(args.pack())
                .code_hash(sighash_all_cell_data_hash.clone())
                .hash_type(sighash_all_cell_hash_type.into())
                .build();
            let previous_output_cell = CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .lock(script)
                .build();
            dummy.cells.insert(
                previous_out_point.clone(),
                (previous_output_cell.clone(), Bytes::new()),
            );
            let mut random_extra_witness = [0u8; 64];
            rng.fill(&mut random_extra_witness);

            let witness_args = WitnessArgsBuilder::default()
                .input_type(Some(Bytes::from(random_extra_witness.to_vec())).pack())
                .build();
            tx_builder = tx_builder
                .input(CellInput::new(previous_out_point, 0))
                .witness(witness_args.as_bytes().pack());
        }
    }

    tx_builder.build()
}

#[derive(Serialize, Deserialize)]
struct EntryType {
    code_hash: [u8; 32],
    hash_type: u8,
    entry_category: u8,
}

pub fn gen_args(config: &TestConfig) -> Bytes {
    do_gen_args(config, None)
}

pub fn gen_args_with_pub_key_hash(config: &TestConfig, pub_key_hash: Vec<u8>) -> Bytes {
    do_gen_args(config, Some(pub_key_hash))
}

pub fn do_gen_args(config: &TestConfig, pub_key_hash: Option<Vec<u8>>) -> Bytes {
    if config.custom_args {
        return config.auth.custom_args();
    }
    let mut ckb_auth_type = CkbAuthType {
        algorithm_id: config
            .auth
            .get_algorithm_type()
            .try_into()
            .unwrap_or(AuthAlgorithmIdType::Ckb),
        pubkey_hash: [0; 20],
    };

    let hash_type: u8 = match &config.script_hash_type {
        Some(t) => t.clone(),
        None => ScriptHashType::Data2.into(),
    };

    let mut entry_type = EntryType {
        code_hash: [0; 32],
        hash_type,
        entry_category: config.entry_category_type.clone() as u8,
    };

    if !config.incorrect_pubkey {
        let pub_hash = pub_key_hash.unwrap_or(config.auth.get_pub_key_hash());
        assert_eq!(pub_hash.len(), 20);
        ckb_auth_type
            .pubkey_hash
            .copy_from_slice(pub_hash.as_slice());
    } else {
        let mut rng = thread_rng();
        let incorrect_pubkey = {
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            Vec::from(buf)
        };
        ckb_auth_type
            .pubkey_hash
            .copy_from_slice(&incorrect_pubkey.as_slice()[0..20]);
    }

    let sighash_all_cell_data_hash: Byte32 =
        CellOutput::calc_data_hash(&config.auth_script_type.get_bin());
    entry_type
        .code_hash
        .copy_from_slice(sighash_all_cell_data_hash.as_slice());

    let mut bytes = BytesMut::with_capacity(size_of::<CkbAuthType>() + size_of::<EntryType>());
    bytes.put_u8(config.auth.get_algorithm_type()); // Need to test algorithm_id out of range
    bytes.put(Bytes::from(ckb_auth_type.pubkey_hash.to_vec()));

    bytes.put(Bytes::from(bincode::serialize(&entry_type).unwrap()));

    bytes.freeze()
}

pub fn build_resolved_tx(
    data_loader: &DummyDataLoader,
    tx: &TransactionView,
) -> ResolvedTransaction {
    let resolved_cell_deps = tx
        .cell_deps()
        .into_iter()
        .map(|deps_out_point| {
            let (dep_output, dep_data) =
                data_loader.cells.get(&deps_out_point.out_point()).unwrap();
            CellMetaBuilder::from_cell_output(dep_output.to_owned(), dep_data.to_owned())
                .out_point(deps_out_point.out_point())
                .build()
        })
        .collect();

    let mut resolved_inputs = Vec::new();
    for i in 0..tx.inputs().len() {
        let previous_out_point = tx.inputs().get(i).unwrap().previous_output();
        let (input_output, input_data) = data_loader.cells.get(&previous_out_point).unwrap();
        resolved_inputs.push(
            CellMetaBuilder::from_cell_output(input_output.to_owned(), input_data.to_owned())
                .out_point(previous_out_point)
                .build(),
        );
    }

    ResolvedTransaction {
        transaction: tx.clone(),
        resolved_cell_deps,
        resolved_inputs,
        resolved_dep_groups: vec![],
    }
}

pub fn debug_printer(_script: &Byte32, msg: &str) {
    /*
    let slice = _script.as_slice();
    let str = format!(
        "Script({:x}{:x}{:x}{:x}{:x})",
        slice[0], slice[1], slice[2], slice[3], slice[4]
    );
    println!("{:?}: {}", str, msg);
    */
    println!("{}", msg);
}

pub struct MyLogger;

impl log::Log for MyLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        println!("{}:{} - {}", record.level(), record.target(), record.args());
    }
    fn flush(&self) {}
}

pub enum AuthErrorCodeType {
    NotImplemented = 100,
    Mismatched,
    InvalidArg,
    ErrorWrongState,
    // exec
    ExecInvalidLength,
    ExecInvalidParam,
    ExecNotPaired,
    ExecInvalidSig,
    ExecInvalidMsg,
}

pub fn assert_script_error(err: Error, err_code: AuthErrorCodeType, des: &str) {
    let err_code = err_code as i8;
    let error_string = err.to_string();
    assert!(
        error_string.contains(format!("error code {}", err_code).as_str()),
        "{}, error string: {}, expected error code: {}",
        des,
        error_string,
        err_code
    );
}

pub fn assert_script_error_vec(err: Error, err_codes: &[i32]) {
    let error_string = err.to_string();
    let mut is_assert = false;
    for err_code in err_codes {
        if error_string.contains(format!("error code {}", err_code).as_str()) {
            is_assert = true;
            break;
        }
    }

    if !is_assert {
        assert!(false, "error_string: {}", error_string);
    }
}

pub fn assert_script_error_i(err: Error, err_code: i32) {
    let err_code = err_code as i8;
    let error_string = err.to_string();
    assert!(
        error_string.contains(format!("error code {}", err_code).as_str()),
        "error_string: {}, expected_error_code: {}",
        error_string,
        err_code
    );
}

pub fn gen_tx_scripts_verifier(
    tx: TransactionView,
    data_loader: DummyDataLoader,
) -> TransactionScriptsVerifier<DummyDataLoader> {
    use ckb_types::core::hardfork::HardForks;

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(HardForks::new_dev())
        .build();

    let mut verifier = TransactionScriptsVerifier::new(
        Arc::new(resolved_tx),
        data_loader.clone(),
        Arc::new(consensus),
        Arc::new(TxVerifyEnv::new_commit(
            &HeaderView::new_advanced_builder().build(),
        )),
    );
    verifier.set_debug_printer(debug_printer);
    verifier
}
