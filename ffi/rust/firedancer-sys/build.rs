use std::{
    env,
    path::{
        Path,
        PathBuf,
    },
    process::Command,
};

extern crate bindgen;

fn main() {
    let dir_env = env::var("CARGO_MANIFEST_DIR").unwrap();
    let dir = Path::new(&dir_env);
    let firedancer_dir = dir.join("firedancer");

    let (machine, build_dir) = if cfg!(feature = "fuzz-asan") {
        (
            "linux_clang_fuzz_asan",
            firedancer_dir.join("build/linux/clang/fuzz_asan"),
        )
    } else {
        (
            "linux_clang_x86_64_pic",
            firedancer_dir.join("build/linux/clang/x86_64_pic"),
        )
    };

    // Build the Firedancer sources
    Command::new("make")
        .arg("-j")
        .arg("lib")
        .arg("include")
        .current_dir(&firedancer_dir)
        .env("MACHINE", machine)
        .output()
        .expect("failed to build firedancer sources");

    // Link against the Firedancer sources
    println!(
        "cargo:rustc-link-search=all={}",
        build_dir
            .join("lib")
            .to_str()
            .expect("failed to convert path to string")
    );
    println!(
        "cargo:rerun-if-changed={}",
        build_dir
            .to_str()
            .expect("failed to convert path to string")
    );
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rustc-link-lib=static=fd_util");
    println!("cargo:rustc-link-lib=static=fd_tango");
    println!("cargo:rustc-link-lib=static=fd_disco");
    println!("cargo:rustc-link-lib=static=fd_ballet");
    println!("cargo:rustc-link-lib=stdc++");

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
