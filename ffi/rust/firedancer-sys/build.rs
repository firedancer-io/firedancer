use std::env;
use std::path::Path;
use std::process::Command;

extern crate bindgen;

fn main() {
    let dir_env = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir_env = env::var("OUT_DIR").unwrap();
    let dir = Path::new(&dir_env);
    let out_dir = Path::new(&out_dir_env);

    let machine = "native_ffi";
    let build_dir = out_dir.join("build/native_ffi/gcc");

    let prefix = if dir.join("staging").exists() {
        // Make sure we're actually in `cargo package`, if not the
        // `staging` directory shouldn't exist. See `publish.sh`
        assert!(
            env::var("CARGO_MANIFEST_DIR")
                .unwrap()
                .contains("package/firedancer-sys"),
            "staging subdirectory exists but we not running in `cargo package` see `publish.sh`"
        );

        // We're in the packaged version, someone has already setup the
        // staging subdirectory with all the C code and headers.
        //
        // No `rerun-if-changed`, the manifest include is correct.
        "staging"
    } else {
        // Make sure we're not in `cargo package`, if we are, the
        // `staging` subdirectory should exist.
        assert!(!env::var("CARGO_MANIFEST_DIR")
            .unwrap()
            .contains("package/firedancer-sys"));

        // There's no point emitting a `rerun-if-changed` for the Makefile
        // or any build system related files, because Make itself can't
        // detect changes in this, and think it's already built correctly.
        //
        // We would need to `cargo clean` if any Makefile changes, which
        // isn't possible now.
        println!("cargo:rerun-if-changed=wrapper_util.h");
        println!("cargo:rerun-if-changed=../../../src/util");
        println!("cargo:rerun-if-changed=wrapper_ballet.h");
        println!("cargo:rerun-if-changed=../../../src/ballet");
        println!("cargo:rerun-if-changed=wrapper_tango.h");
        println!("cargo:rerun-if-changed=../../../src/tango");

        "../../../"
    };

    for lib in ["util", "ballet", "tango"] {
        // Generate bindings to the header files
        let mut builder = bindgen::Builder::default()
            .wrap_static_fns(true)
            .wrap_static_fns_path(out_dir.join(&format!("gen_{lib}.c")))
            .allowlist_recursively(false)
            .default_non_copy_union_style(bindgen::NonCopyUnionStyle::ManuallyDrop)
            .clang_arg("-DFD_HAS_FFI=1")
            .clang_arg(format!("-I{prefix}/"))
            .clang_arg("-std=c17")
            .header(&format!("wrapper_{lib}.h"))
            .blocklist_type("schar|uchar|ushort|uint|ulong")
            .blocklist_item("SORT_QUICK_ORDER_STYLE|SORT_MERGE_THRESH|SORT_QUICK_THRESH|SORT_QUICK_ORDER_STYLE|SORT_QUICK_SWAP_MINIMIZE");

        // Well this is a complete mess. We want to only include, say, functions
        // declared in the `ballet` directory in the ballet bindgen output. If
        // we include all the util stuff that it #includes, it will get defined
        // by every lib in turn and produce errors.
        //
        // Unfortunately, the only control we have over this is a regex "blocklist
        // file". There's an "allow list" but it can only cause otherwise blocked
        // items to be included, not being on the allow list doesn't make you
        // blocked.
        //
        // So we have to use this blocklist. It's Rust regex crate, so no
        // lookbehind so this is going to be pretty painful...
        //
        // It's annoying to debug as well. The easiest way I found is editing
        // `ir/item.rs` in the local bindgen crate source to add println!
        // when it blocks or allows, and then scanning the build output file.
        // If one of the regular expressions is not valid, bingden will just
        // silently ignore all of the other blocklists and allow everything.
        //
        // // ir/item.rs:652
        // if let Some(filename) = file.name() {
        //     if ctx.options().blocklisted_files.matches(&filename) {
        //         println!("BLOCK true {}", filename);
        //         return true;
        //     }
        //     println!("BLOCK false {}", filename);
        // }

        match prefix {
            "staging" => {
                // All of our headers and code are referenced like `staging/src/..`
                // so if something does not start with `staging/` it's a system header
                // and we should block it.
                builder = builder.blocklist_file("[^s].*");
                builder = builder.blocklist_file("s[^t].*");
                builder = builder.blocklist_file("st[^a].*");
                builder = builder.blocklist_file("sta[^g].*");
                builder = builder.blocklist_file("stag[^i].*");
                builder = builder.blocklist_file("stagi[^n].*");
                builder = builder.blocklist_file("stagin[^g].*");
                builder = builder.blocklist_file("staging[^/].*");
            }
            "../../../" => {
                // Same but referenced like "../../../src.."
                builder = builder.blocklist_file("[^\\.].*");
                builder = builder.blocklist_file("\\.[^\\.].*");
                builder = builder.blocklist_file("\\.\\.[^/].*");
            }
            _ => unreachable!(),
        };

        // Now basically we want to say, if we are building `tango` we allow
        // anything that looks like `staging/src/tango/...`
        //
        // To do this with the blocklist, we just look at all the directories
        // in `staging/src/` that are not `tango`, and block those.
        for dir in std::fs::read_dir(format!("{prefix}/src")).unwrap() {
            let dir = dir.unwrap().file_name();
            let dir = dir.to_str().unwrap();
            if dir != lib {
                // Most includes are actually going to look like `staging/src/tango/../util/`
                // so it's not enough to check the `src/other` path. We also need to check that
                // there is no `../other` for these other libraries.
                //
                // Well.. except a special case. If we are in a template file like `tmpl/fd_map.c`
                // it actually *should* be exported, because even though it's kind-of declared in
                // the util folder, it's unique to the #including lib.
                if lib == "util" || dir != "util" {
                    // `util` just shouldn't include `../tango` or anything else. And there
                    // are no templates in non-util subdirs so block those.
                    builder = builder.blocklist_file(&format!(".*/\\.\\./{}/.*", dir));
                } else {
                    // For the other packages, block if it's not ending in `/tmpl/*`
                    // staging/src/ballet/sbpf/../../util/tmpl/fd_map.c -> allow
                    // staging/src/ballet/sbpf/../../util/fd_util_base.h -> deny
                    builder = builder.blocklist_file(".*/\\.\\./util/[^/]+");
                    builder = builder.blocklist_file(".*/\\.\\./util/(.*/)?[^t][^/]+/[^/]+");
                    builder = builder.blocklist_file(".*/\\.\\./util/(.*/)?t[^m][^/]+/[^/]+");
                    builder = builder.blocklist_file(".*/\\.\\./util/(.*/)?tm[^p][^/]+/[^/]+");
                    builder = builder.blocklist_file(".*/\\.\\./util/(.*/)?tmp[^l][^/]+/[^/]+");
                    builder = builder.blocklist_file(".*/\\.\\./util/(.*/)?tmpl[^/][^/]+/[^/]+");
                }

                // Only declare templates that are actually defined in this library,
                // deny ones that come from some other include. Eg, below the template
                // comes from util/math not ballet, so we don't want it.
                // staging/src/ballet/../util/math/../tmpl/fd_sort.c -> deny
                builder = builder.blocklist_file(&format!(".*\\.\\./{}/.*/tmpl/[^/]+", dir));
            }
        }

        builder
            .generate()
            .expect("Unable to generate bindings")
            .write_to_file(out_dir.join(&format!("bindings_{lib}.rs")))
            .expect("Failed to write bindings to file");

        // Build the Firedancer sources
        let mut command = Command::new("make");
        command
            .arg("-j")
            .arg(format!("{}/lib/libfd_{lib}.a", build_dir.display()))
            .current_dir(&dir.join(prefix))
            .env("MACHINE", machine)
            .env("BASEDIR", out_dir.join("build"));

        let key = format!("{}_STATIC_EXTERN_OBJECT", lib.to_uppercase());
        let value = out_dir.join(&format!("gen_{}.c", lib));
        command.env(key, value);

        let output = command.output().unwrap_or_else(|_| {
            panic!(
                "failed to execute `make`, does it exist? PATH {:#?}",
                std::env::var("PATH")
            )
        });
        if !output.status.success() {
            panic!(
                "{}\n{}",
                String::from_utf8(output.stdout).unwrap(),
                String::from_utf8(output.stderr).unwrap()
            );
        }
    }

    // Link against the Firedancer sources
    println!(
        "cargo:rustc-link-search=all={}",
        build_dir
            .join("lib")
            .to_str()
            .expect("failed to convert path to string")
    );
    println!("cargo:rustc-link-lib=static=fd_util");
    println!("cargo:rustc-link-lib=static=fd_tango");
    println!("cargo:rustc-link-lib=static=fd_ballet");
    println!("cargo:rustc-link-lib=stdc++");
}
