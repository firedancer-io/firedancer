use ed25519_dalek::{Signature, VerifyingKey};
use std::ffi::c_int;

#[no_mangle]
pub extern "C" fn ed25519_dalek_verify(
    msg: *const u8,
    sz: u64,
    sig: *const u8,
    public_key: *const u8,
) -> c_int {
    let signature =
        Signature::from_bytes(unsafe { std::slice::from_raw_parts(sig, 64).try_into().unwrap() });
    let verifying_key = match VerifyingKey::from_bytes(unsafe {
        std::slice::from_raw_parts(public_key, 32)
            .try_into()
            .unwrap()
    }) {
        Ok(vk) => vk,
        Err(_) => return 0,
    };
    verifying_key
        .verify_strict(
            unsafe { std::slice::from_raw_parts(msg, sz as usize) },
            &signature,
        )
        .is_ok() as c_int
}
