use crate::{
    on_chain_script::{AuthLockScriptType, AuthScriptType},
    Auth,
};
use ckb_auth_rs::{AuthAlgorithmIdType, EntryCategoryType};

#[derive(PartialEq, Eq)]
pub enum TestConfigIncorrectSing {
    None,
    Bigger,
    Smaller,
}

pub struct TestConfig {
    pub auth: Box<dyn Auth>,
    pub entry_category_type: EntryCategoryType,

    pub inputs_size: i32,

    pub incorrect_pubkey: bool,
    pub incorrect_msg: bool,
    pub incorrect_sign: bool,
    pub incorrect_sign_size: TestConfigIncorrectSing,

    pub auth_script_type: AuthScriptType,
    pub auth_lock_type: AuthLockScriptType,
    // pub auth_bin: Option<Bytes>,
    pub script_hash_type: Option<u8>,

    pub custom_args: bool,
    pub load_all_auth: bool,
}

impl TestConfig {
    pub fn new(
        auth: &Box<dyn Auth>,
        entry_category_type: EntryCategoryType,
        inputs_size: i32,
    ) -> TestConfig {
        assert!(inputs_size > 0);
        let auth_id_secp256r1: u8 = AuthAlgorithmIdType::Secp256r1.clone().into();

        TestConfig {
            auth: auth.clone(),
            entry_category_type,
            inputs_size,
            incorrect_pubkey: false,
            incorrect_msg: false,
            incorrect_sign: false,
            incorrect_sign_size: TestConfigIncorrectSing::None,
            auth_script_type: if auth.get_algorithm_type() == auth_id_secp256r1 {
                AuthScriptType::Libecc
            } else {
                AuthScriptType::Original
            },
            auth_lock_type: AuthLockScriptType::C,
            script_hash_type: None,
            custom_args: false,
            load_all_auth: false,
        }
    }
}
