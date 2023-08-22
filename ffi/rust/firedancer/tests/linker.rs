use firedancer::*;

#[test]
fn links_properly() {
    let gaddr = GlobalAddress::try_from("".to_string()).unwrap();
    assert!(unsafe { MCache::join(gaddr) }.is_err());
}
