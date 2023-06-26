
extern crate hex;
extern crate serde_json;

use bv::BitVec;

use serde::Serialize;

#[derive(Serialize)]
pub struct Foo {
    pub a: BitVec<u64>,
    pub b : u64
}

fn main() {
    let mut s = Foo {
        a: BitVec::new(),
        b: 5
    };

    s.a.push(true);
    s.a.push(false);
    s.a.push(true);
    s.a.push(true);
    s.a.push(false);
    s.a.push(true);

    let d2: Vec<u8> = bincode::serialize(&s).unwrap();
//    println!("hex: {}",  hex::encode(d2));
    println!("Account: {} {}", serde_json::to_string(&s).unwrap(), hex::encode(d2));

}
