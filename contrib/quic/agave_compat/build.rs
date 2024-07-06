use std::env;
use std::path::PathBuf;

fn main() {
    let mut lib_path = PathBuf::new().join(env::var("CARGO_MANIFEST_DIR").unwrap());
    lib_path.pop();
    lib_path.pop();
    lib_path.pop();
    lib_path.push("build");
    lib_path.push("native");
    lib_path.push("gcc");
    lib_path.push("lib");
    println!("cargo:rustc-link-search={}", lib_path.to_str().unwrap());
}
