use firedancer::*;

#[test]
fn lifecycle() {
    fd_boot(&[
        "--log-app",
        "rust",
        "--log-level-stderr",
        "0",
        "--log-path",
        "",
    ]);
    unsafe {
        fd_halt();
    }
}
