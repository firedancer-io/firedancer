use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};
use std::ffi::c_int;

#[no_mangle]
pub extern "C" fn ed25519_dalek_sign(
    sig: *mut u8,
    msg: *const u8,
    sz: u64,
    public_key: *const u8,
    private_key: *const u8,
) -> c_int {
    let secret = match SecretKey::from_bytes(unsafe {
        std::slice::from_raw_parts(private_key, 32)
            .try_into()
            .unwrap()
    }) {
        Ok(sk) => sk,
        Err(_) => return -1,
    };

    let public = match PublicKey::from_bytes(unsafe {
        std::slice::from_raw_parts(public_key, 32)
            .try_into()
            .unwrap()
    }) {
        Ok(pk) => pk,
        Err(_) => return -1,
    };

    let keypair = Keypair {
        secret: secret,
        public: public,
    };

    let signature = keypair.sign(unsafe { std::slice::from_raw_parts(msg, sz as usize) });

    unsafe {
        std::ptr::copy_nonoverlapping(&signature.to_bytes() as *const u8, sig, 64);
    }
    return 0; // success
}

#[no_mangle]
pub extern "C" fn ed25519_dalek_verify(
    msg: *const u8,
    sz: u64,
    sig: *const u8,
    public_key: *const u8,
) -> c_int {
    let signature = match Signature::from_bytes(unsafe {
        std::slice::from_raw_parts(sig, 64)
            .try_into()
            .unwrap()
    }) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let public = match PublicKey::from_bytes(unsafe {
        std::slice::from_raw_parts(public_key, 32)
            .try_into()
            .unwrap()
    }) {
        Ok(pk) => pk,
        Err(_) => return -1,
    };

    let ok = public
        .verify_strict(
            unsafe { std::slice::from_raw_parts(msg, sz as usize) },
            &signature,
        )
        .is_ok();

    return if ok { 0 } else { -1 };
}
