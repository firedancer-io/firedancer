extern crate bindgen;

use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rustc-link-search=all=assets/lib");
    println!("cargo:rustc-link-lib=static=fd_util");
    println!("cargo:rustc-link-lib=static=fd_tango");
    println!("cargo:rustc-link-lib=static=fd_disco");
    println!("cargo:rustc-link-lib=static=fd_ballet");
    println!("cargo:rustc-link-lib=numa");
    println!("cargo:rustc-link-lib=stdc++");

    println!("cargo:rerun-if-changed=assets/include/fd_linux_clang_x86_64.h");
    println!("cargo:rerun-if-changed=assets/include/fd_ballet.h");
    println!("cargo:rerun-if-changed=assets/include/fd_disco.h");

    let bindings = bindgen::Builder::default()
        .header("assets/include/fd_linux_clang_x86_64.h")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("src/fd_ffi.rs"))
        .expect("Couldn't write bindings!");
}
