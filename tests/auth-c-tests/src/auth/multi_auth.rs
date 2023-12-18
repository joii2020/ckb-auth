use crate::{
    auth::auth_builder, on_chain_script::AuthLockScriptType, on_chain_script::AuthScriptType,
    test_config::TestConfig, Auth,
};
use ckb_auth_rs::{AuthAlgorithmIdType, EntryCategoryType};
use ckb_types::{
    bytes::{BufMut, Bytes, BytesMut},
    H256,
};

#[derive(Clone)]
pub struct MultiAuthItem {
    pub auth_id: AuthAlgorithmIdType,
    pub auth: Box<dyn Auth>,
    pub auth_script_type: AuthScriptType,
    pub entry_category: EntryCategoryType,
}
impl MultiAuthItem {
    pub fn new(auth_id: AuthAlgorithmIdType, entry_category: EntryCategoryType) -> Self {
        Self {
            auth_id: auth_id.clone(),
            auth: auth_builder(auth_id.clone(), false).expect("auth builder"),
            auth_script_type: AuthScriptType::Original,
            entry_category,
        }
    }
    pub fn new_by_dl(auth_id: AuthAlgorithmIdType) -> Self {
        Self::new(auth_id, EntryCategoryType::DynamicLibrary)
    }
}

#[derive(Clone)]
pub struct MultiAuth {
    items: Vec<MultiAuthItem>,
}
impl MultiAuth {
    pub fn new(items: &[MultiAuthItem]) -> Box<dyn Auth> {
        assert!(items.len() < 255);
        Box::new(Self {
            items: items.to_vec(),
        })
    }

    pub fn new_config(items: &[MultiAuthItem]) -> TestConfig {
        let auth = Self::new(items);

        let mut config = TestConfig::new(&auth, EntryCategoryType::Exec, 1);
        config.auth_lock_type = AuthLockScriptType::CMulti;
        config.custom_args = true;
        config.load_all_auth = true;

        config
    }
}
impl Auth for MultiAuth {
    fn get_pub_key_hash(&self) -> Vec<u8> {
        Vec::new()
    }
    fn get_algorithm_type(&self) -> u8 {
        self.items.len() as u8
    }
    fn convert_message(&self, message: &[u8; 32]) -> H256 {
        H256::from(message.clone())
    }
    fn sign(&self, msg: &H256) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.get_sign_size());
        for item in &self.items {
            let d_msg = item.auth.convert_message(&msg.0);
            let sign_data = item.auth.sign(&d_msg);
            buf.put_u32_le(sign_data.len() as u32);
            buf.put(sign_data)
        }

        Bytes::from(buf)
    }
    fn get_sign_size(&self) -> usize {
        let mut sign_size = 0;
        for item in &self.items {
            sign_size += 4;
            sign_size += item.auth.get_sign_size();
        }
        sign_size
    }

    fn custom_args(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(1 + self.items.len() * 55);
        buf.put_u8(self.items.len() as u8);

        for item in &self.items {
            let mut config = TestConfig::new(&item.auth, item.entry_category.clone(), 1);
            config.auth_script_type = item.auth_script_type.clone();
            let args = crate::do_gen_args(&config, None);
            buf.put(args);
        }

        Bytes::from(buf)
    }
}
