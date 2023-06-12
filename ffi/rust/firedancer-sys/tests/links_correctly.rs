#[test]
fn links_correctly() {
    println!("{}", unsafe { firedancer_sys::util::fd_tile_id() });
}
