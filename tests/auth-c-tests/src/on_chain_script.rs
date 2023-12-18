use ckb_types::bytes::Bytes;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref ORIGINAL_AUTH_PROGRAM: Bytes =
        Bytes::from(&include_bytes!("../../../build/auth")[..]);
    pub static ref LIBECC_AUTH_PROGRAM: Bytes =
        Bytes::from(&include_bytes!("../../../build/auth_libecc")[..]);
    pub static ref AUTH_C_LOCK: Bytes =
        Bytes::from(&include_bytes!("../../../build/auth_c_lock")[..]);
    pub static ref AUTH_RUST_LOCK: Bytes =
        Bytes::from(&include_bytes!("../../../build/auth-rust-demo")[..]);
    pub static ref AUTH_C_LOCK_DISABLE_DL: Bytes =
        Bytes::from(&include_bytes!("../../../build/auth_c_lock_disable_dl")[..]);
    pub static ref MULTI_AUTH_C_LOCK: Bytes =
        Bytes::from(&include_bytes!("../../../build/multi_auth_c_lock")[..]);
    pub static ref SECP256K1_DATA_BIN: Bytes =
        Bytes::from(&include_bytes!("../../../build/secp256k1_data_20210801")[..]);
    pub static ref ALWAYS_SUCCESS: Bytes =
        Bytes::from(&include_bytes!("../../../build/always_success")[..]);
}

#[derive(PartialEq, Eq)]
pub enum AuthLockScriptType {
    C,
    Rust,
    CDisableDl,
    CMulti,
    Rand(Bytes),
}

impl AuthLockScriptType {
    pub fn get_bin(&self) -> &Bytes {
        match self {
            Self::C => &AUTH_C_LOCK,
            Self::Rust => &AUTH_RUST_LOCK,
            Self::CDisableDl => &AUTH_C_LOCK_DISABLE_DL,
            Self::Rand(auth_bin) => auth_bin,
            Self::CMulti => &MULTI_AUTH_C_LOCK,
        }
    }
}

#[derive(PartialEq, Eq, Clone)]
pub enum AuthScriptType {
    Original,
    Libecc,
}

impl AuthScriptType {
    pub fn get_bin(&self) -> &Bytes {
        match self {
            Self::Original => &ORIGINAL_AUTH_PROGRAM,
            Self::Libecc => &LIBECC_AUTH_PROGRAM,
        }
    }
}
