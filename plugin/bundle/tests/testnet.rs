use std::ffi::CString;

use ed25519_dalek::{ed25519::signature::SignerMut, SigningKey};
use firedancer_plugin_bundle::*;

const PRIVATE_KEY: [u8; 32] = [0; 32];
const PUBLIC_KEY: [u8; 32] = [0; 32];

#[no_mangle]
extern "C" fn plugin_bundle_sign_challenge(challenge: *const i8, result: *mut u8) {
    let challenge = unsafe { std::ffi::CStr::from_ptr(challenge) }
        .to_str()
        .unwrap();
    let result = unsafe { std::slice::from_raw_parts_mut(result, 64) };

    let mut signing_key: SigningKey = SigningKey::from_bytes(&PRIVATE_KEY);
    let signature = signing_key
        .sign(format!("{}-{}", bs58::encode(PUBLIC_KEY).into_string(), challenge).as_bytes());

    result.copy_from_slice(&signature.to_bytes());
}

#[test]
fn testnet() {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("trace"));

    let url = CString::new(env!("FD_BLOCK_ENGINE_URL")).unwrap();

    let bundle = plugin_bundle_init(url.as_ptr(), PUBLIC_KEY.as_ptr());
    assert!(!bundle.is_null());

    loop {
        let mut out_bundle_len: u64 = 0;
        let mut data: [u8; 6200] = [0; 6200];

        let mut block_builder_pubkey: [u8; 32] = [0; 32];
        let mut block_builder_commission: u64 = 0;

        plugin_bundle_poll(
            bundle,
            block_builder_pubkey.as_mut_ptr(),
            &mut block_builder_commission as &mut u64,
            &mut out_bundle_len as *mut u64,
            data.as_mut_ptr(),
        );
        if out_bundle_len != 0 {
            log::warn!(
                "Got bundle of len: {}, commission {}, block builder {}",
                out_bundle_len,
                block_builder_commission,
                bs58::encode(block_builder_pubkey).into_string()
            );
        }
    }
}
