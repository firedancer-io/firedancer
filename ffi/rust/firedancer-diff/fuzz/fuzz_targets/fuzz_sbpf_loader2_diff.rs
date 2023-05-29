#![no_main]

extern crate libfuzzer_sys;
use firedancer_diff::{load_program_labs, load_program_firedancer};

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn rust_fuzzer_test_input(bytes: &[u8]) -> i32 {
    if libfuzzer_sys::RUST_LIBFUZZER_DEBUG_PATH.get().is_some() {
        // Override debug print handler to skip rust-fuzz's annoying
        // very long stderr spam.
        return 0;
    }
    __libfuzzer_sys_run(bytes);
    0
}

#[inline(never)]
fn __libfuzzer_sys_run(bytes: &[u8]) {
    let prog_sl_res = load_program_labs(bytes);
    let prog_fd_res = load_program_firedancer(bytes.to_vec());
    assert_eq!(prog_sl_res.is_ok(), prog_fd_res.is_ok(), "one loaded, one failed");

    let (prog_sl, prog_fd) = match (prog_sl_res, prog_fd_res) {
        (Err(_), Err(_)) => return,
        (Ok(prog_sl), Ok(prog_fd)) => (prog_sl, prog_fd),
        _ => unreachable!(),
    };

    assert_eq!(prog_sl, prog_fd, "programs didn't load identically");
}
