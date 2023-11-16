#[test]
fn links_correctly() {
    println!("{}", unsafe { firedancer_sys::util::fd_tile_id() });
}

#[test]
fn links_static_inline_correctly() {
    println!("{:?}", unsafe {
        firedancer_sys::tango::fd_cnc_app_laddr(std::ptr::null_mut())
    });
}
