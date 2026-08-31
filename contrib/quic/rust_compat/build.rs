use std::env;
use std::path::{Path, PathBuf};

fn main() {
    let firedancer_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("failed to locate Firedancer root")
        .to_path_buf();

    // build dir is compiler-keyed: take OBJDIR from the env or ask make;
    // every input to the key (env, compiler binary, make config) must
    // re-run this script
    for v in [
        "OBJDIR",
        "MACHINE",
        "CC",
        "PATH",
        "EXTRAS",
        "BASEDIR",
        "BUILDDIR",
        "BUILDDIR1",
    ] {
        println!("cargo:rerun-if-env-changed={}", v);
    }
    let root = firedancer_path.to_str().unwrap();
    println!("cargo:rerun-if-changed={}/Makefile", root);
    println!("cargo:rerun-if-changed={}/config", root);
    let out = std::process::Command::new("make")
        .args(["--silent", "--no-print-directory", "-C", root, "env"])
        .output()
        .expect("failed to run make env");
    assert!(
        out.status.success(),
        "make env failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mk_env = String::from_utf8(out.stdout).unwrap();
    let mk_var = |k: &str| {
        mk_env
            .lines()
            .find_map(|l| l.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
            .map(|v| v.trim_matches('\'').to_string())
            .expect(k)
    };
    if let Ok(out) = std::process::Command::new("sh")
        .args([
            "-c",
            &format!(
                "command -v {}",
                mk_var("CC").split_whitespace().next().unwrap_or("cc")
            ),
        ])
        .output()
    {
        let cc = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if let Ok(cc) = std::fs::canonicalize(&cc) {
            println!("cargo:rerun-if-changed={}", cc.display());
        }
    }
    let objdir = env::var("OBJDIR").unwrap_or_else(|_| mk_var("OBJDIR"));
    let build_path = firedancer_path.join(&objdir);

    let mut lib_path = build_path.clone();
    lib_path.push("lib");
    println!("cargo:rustc-link-search={}", lib_path.to_str().unwrap());

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
