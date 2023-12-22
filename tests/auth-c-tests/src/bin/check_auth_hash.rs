use ckb_auth_rs::load_library::*;
use ckb_types::packed::CellOutput;
use lazy_static::lazy_static;

lazy_static! {
    static ref AUTH_ON_CHAIN_SCRIPT_2: Vec<u8> = include_bytes!("../../../../build/auth").to_vec();
    static ref AUTH_LIBECC_ON_CHAIN_SCRIPT_2: Vec<u8> =
        include_bytes!("../../../../build/auth_libecc").to_vec();
    static ref SECP256K1_DATA_BIN_2: Vec<u8> =
        include_bytes!("../../../../build/secp256k1_data_20210801").to_vec();
}

fn get_script_hash(bin: &[u8]) -> Vec<u8> {
    let hash = CellOutput::calc_data_hash(bin).raw_data().to_vec();

    // print!("[");
    // for c in &hash {
    //     print!("0x{:02x?}, ", c);
    // }
    // println!("]");

    hash
}

fn check_ckb_auth_rs_bin() {
    assert_eq!(
        get_script_hash(&AUTH_ON_CHAIN_SCRIPT),
        AUTH_ON_CHAIN_SCRIPT_HASH.to_vec()
    );

    assert_eq!(
        get_script_hash(&AUTH_LIBECC_ON_CHAIN_SCRIPT),
        AUTH_LIBECC_ON_CHAIN_SCRIPT_HASH.to_vec()
    );

    assert_eq!(
        get_script_hash(&SECP256K1_DATA_BIN),
        SECP256K1_DATA_BIN_HASH.to_vec()
    );
}

fn check_build_bin() {
    assert_eq!(
        get_script_hash(&AUTH_ON_CHAIN_SCRIPT_2),
        AUTH_ON_CHAIN_SCRIPT_HASH.to_vec()
    );

    assert_eq!(
        get_script_hash(&AUTH_LIBECC_ON_CHAIN_SCRIPT_2),
        AUTH_LIBECC_ON_CHAIN_SCRIPT_HASH.to_vec()
    );

    assert_eq!(
        get_script_hash(&SECP256K1_DATA_BIN_2),
        SECP256K1_DATA_BIN_HASH.to_vec()
    );
}

fn main() {
    check_ckb_auth_rs_bin();
    check_build_bin();
}
