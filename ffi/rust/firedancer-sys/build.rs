use std::env;
use std::path::Path;
use std::process::Command;

extern crate bindgen;

fn main() {
    let dir_env = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir_env = env::var("OUT_DIR").unwrap();
    let dir = Path::new(&dir_env);
    let out_dir = Path::new(&out_dir_env);

    let (machine, build_dir) = if cfg!(feature = "fuzz-asan") {
        (
            "linux_clang_x86_64_fuzz_asan",
            out_dir.join("build/linux/clang/fuzz_asan"),
        )
    } else {
        (
            "linux_clang_x86_64_ffi",
            out_dir.join("build/linux/clang/x86_64_ffi"),
        )
    };

    for lib in ["util", "ballet", "tango", "disco"] {
        // Generate bindings to the header files
        let mut builder = bindgen::Builder::default()
            .wrap_static_fns(true)
            .wrap_static_fns_path(out_dir.join(&format!("gen_{lib}.c")))
            .allowlist_recursively(false)
            .default_non_copy_union_style(bindgen::NonCopyUnionStyle::ManuallyDrop)
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
        // `context/item.rs` in the local bindgen crate source to add println!
        // when it blocks or allows, and then scanning the build output file.
        // If one of the regular expressions is not valid, bingden will just
        // silently ignore all of the other blocklists and allow everything.
        //
        // // context/item.rs:652
        // if let Some(filename) = file.name() {
        //     if ctx.options().blocklisted_files.matches(&filename) {
        //         println!("BLOCK true {}", filename);
        //         return true;
        //     }
        //     println!("BLOCK false {}", filename);
        // }
        //
        // All of our headers and code are referenced like `./firedancer/src/..`
        // so if something does not start with `./` it's a system header and we
        // should block it. Both of these two rules check this.
        builder = builder.blocklist_file("[^\\.].*");
        builder = builder.blocklist_file("\\.[^/].*");

        // Now basically we want to say, if we are building `tango` we allow
        // anything that looks like `./firedancer/src/tango/...`
        //
        // To do this with the blocklist, we just look at all the directories
        // in `./firedancer/src/` that are not `tango`, and block those.
        for dir in std::fs::read_dir("firedancer/src").unwrap() {
            let dir = dir.unwrap().file_name();
            let dir = dir.to_str().unwrap();
            if dir != lib {
                // Block all top level uses of other libraries.
                builder = builder.blocklist_file(&format!("\\.firedancer/src/{}/.*", dir));

                // Most includes are actually going to look like `.firedancer/src/tango/../util/`
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
                    // ./firedancer/src/ballet/sbpf/../../util/tmpl/fd_map.c -> allow
                    // ./firedancer/src/ballet/sbpf/../../util/fd_util_base.h -> deny
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
                // ./firedancer/src/ballet/../util/math/../tmpl/fd_sort.c -> deny
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
            .current_dir(&dir.join("firedancer"))
            .env("MACHINE", machine)
            .env("BASEDIR", out_dir.join("build"));

        // No statics in disco yet so no extern wrapper file is produced
        if lib != "disco" {
            let key = format!("{}_STATIC_EXTERN_OBJECT", lib.to_uppercase());
            let value = out_dir.join(&format!("gen_{}.c", lib));
            command.env(key, value);
        }

        let output = command.output().unwrap_or_else(|_| {
            panic!(
                "failed to execute `make`, does it exist? PATH {:#?}",
                std::env::var("PATH")
            )
        });
        if !output.status.success() {
            panic!("{}", String::from_utf8(output.stderr).unwrap());
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
    println!(
        "cargo:rerun-if-changed={}",
        dir.join("firedancer")
            .to_str()
            .expect("failed to convert path to string")
    );
    println!("cargo:rustc-link-lib=static=fd_util");
    println!("cargo:rustc-link-lib=static=fd_tango");
    println!("cargo:rustc-link-lib=static=fd_disco");
    println!("cargo:rustc-link-lib=static=fd_ballet");
    println!("cargo:rustc-link-lib=stdc++");
}
