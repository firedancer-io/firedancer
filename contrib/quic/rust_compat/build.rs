use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let firedancer_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("failed to locate Firedancer root")
        .to_path_buf();

    let mut build_path = firedancer_path.clone();
    build_path.push("build");
    build_path.push("native");
    build_path.push("gcc");

    let mut lib_path = build_path.clone();
    lib_path.push("lib");
    println!("cargo:rustc-link-search={}", lib_path.to_str().unwrap());

    let opt_lib_path = firedancer_path.join("opt").join("lib");
    println!("cargo:rustc-link-search={}", opt_lib_path.to_str().unwrap());
    for lib in &[
        "fd_quic",
        "fd_waltz", // net
        "fd_tls",
        "fd_tango",  // spmc queues
        "fd_ballet", // crypto
        "fd_util",
    ] {
        println!("cargo:rustc-link-lib=static={}", lib);
        println!(
            "cargo:rerun-if-changed={}/lib{}.a",
            lib_path.to_str().unwrap(),
            lib
        );
    }

    println!("cargo:rustc-link-lib=static=s2nbignum");
    println!(
        "cargo:rerun-if-changed={}",
        opt_lib_path.join("libs2nbignum.a").to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=stdc++");

    let mut include_path = build_path.clone();
    include_path.push("include");

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(&["-isystem", include_path.to_str().unwrap(), "-std=c17"])
        .allowlist_type("fd_.*")
        .allowlist_function("fd_.*")
        .allowlist_var("FD_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");
    println!("cargo:rerun-if-changed=wrapper.h");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
