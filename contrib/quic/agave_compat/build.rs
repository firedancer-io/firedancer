use std::env;
use std::path::PathBuf;

fn main() {
    let cargo_manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut build_path = PathBuf::new().join(cargo_manifest_dir);
    build_path.pop();
    build_path.pop();
    build_path.pop();
    build_path.push("build");
    build_path.push("native");
    build_path.push("gcc");

    let mut lib_path = build_path.clone();
    lib_path.push("lib");
    println!("cargo:rustc-link-search={}", lib_path.to_str().unwrap());
    println!("cargo:rustc-link-lib=static=fd_quic");
    println!("cargo:rustc-link-lib=static=fd_waltz"); // net
    println!("cargo:rustc-link-lib=static=fd_tls");
    println!("cargo:rustc-link-lib=static=fd_ballet"); // crypto
    println!("cargo:rustc-link-lib=static=fd_util");
    println!("cargo:rustc-link-lib=static=stdc++"); // fd_tile_threads.cxx

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
