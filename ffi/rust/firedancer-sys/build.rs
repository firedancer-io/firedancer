use std::{
    env,
    path::{Path,PathBuf},
    process::Command,
};

extern crate bindgen;

fn main() {
    let dir_env = env::var("CARGO_MANIFEST_DIR").unwrap();
    let dir = Path::new(&dir_env);
    let firedancer_dir = dir.join("firedancer");
    let machine = "linux_clang_x86_64_ffi_rust".to_string();
    let objdir = firedancer_dir.join("build").join("linux/clang/x86_64");

    // Build the Firedancer sources
    Command::new("make")
        .arg("-j")
        .arg("lib")
        .current_dir(&firedancer_dir)
        .env("MACHINE", machine)
        .output()
        .expect("failed to build firedancer sources");

    // Link against the Firedancer sources
    println!(
        "cargo:rustc-link-search=all={}",
        objdir
            .join("lib")
            .to_str()
            .expect("failed to convert path to string")
    );
    println!(
        "cargo:rerun-if-changed={}",
        objdir.to_str().expect("failed to convert path to string")
    );
    println!("cargo:rustc-link-lib=static=fd_util");
    println!("cargo:rustc-link-lib=static=fd_tango");
    println!("cargo:rustc-link-lib=static=fd_disco");
    println!("cargo:rustc-link-lib=static=fd_ballet");
    println!("cargo:rustc-link-lib=static=fd_xdp");
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=bpf");

    // Generate bindings to the header files
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindgen::Builder::default()
        .header("wrapper.h")
        .blocklist_type("schar|uchar|ushort|uint|ulong")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write bindings to file");
}
