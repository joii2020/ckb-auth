#[cfg(not(target_arch = "riscv64"))]
use alloc::vec::Vec;

pub const AUTH_ON_CHAIN_SCRIPT_HASH: [u8; 32] = [
    0xd3, 0xcf, 0x9d, 0x20, 0x20, 0xe0, 0x6d, 0x76, 0x24, 0x2a, 0xbc, 0xfb, 0x52, 0xdd, 0x2d, 0xb7,
    0xe6, 0xe1, 0xc9, 0x50, 0x59, 0x64, 0xec, 0xf9, 0xeb, 0x9b, 0x36, 0x55, 0x64, 0x2e, 0xa0, 0x6e,
];
pub const AUTH_LIBECC_ON_CHAIN_SCRIPT_HASH: [u8; 32] = [
    0x76, 0x82, 0x85, 0x1c, 0x4b, 0x56, 0xca, 0x26, 0x69, 0xc1, 0xe5, 0x93, 0x76, 0xfd, 0x8f, 0xd8,
    0xca, 0xd0, 0x13, 0x86, 0x48, 0x5c, 0xb4, 0xbb, 0xf0, 0xf8, 0xb2, 0x03, 0x00, 0xb9, 0x3f, 0x1c,
];
pub const SECP256K1_DATA_BIN_HASH: [u8; 32] = [
    0x97, 0x99, 0xbe, 0xe2, 0x51, 0xb9, 0x75, 0xb8, 0x2c, 0x45, 0xa0, 0x21, 0x54, 0xce, 0x28, 0xce,
    0xc8, 0x9c, 0x58, 0x53, 0xec, 0xc1, 0x4d, 0x12, 0xb7, 0xb8, 0xcc, 0xcf, 0xc1, 0x9e, 0x0a, 0xf4,
];

#[cfg(not(target_arch = "riscv64"))]
lazy_static::lazy_static! {
    pub static ref AUTH_ON_CHAIN_SCRIPT: Vec<u8> =
        include_bytes!("../on_chain_script/auth").to_vec();
    pub static ref AUTH_LIBECC_ON_CHAIN_SCRIPT: Vec<u8> =
        include_bytes!("../on_chain_script/auth_libecc").to_vec();
    pub static ref SECP256K1_DATA_BIN: Vec<u8> =
        include_bytes!("../on_chain_script/secp256k1_data_20210801").to_vec();
}
