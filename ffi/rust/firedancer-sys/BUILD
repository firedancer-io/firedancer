load("@rules_rust//bindgen:bindgen.bzl", "rust_bindgen")
load("@rules_rust//rust:defs.bzl", "rust_library")
load("//bazel:fd_build_system.bzl", "fd_cc_library")

fd_cc_library(
    name = "wrapper",
    hdrs = ["wrapper.h"],
    target_compatible_with = ["//bazel/compiler:llvm"],
    deps = [
        "//src/ballet",
        "//src/disco",
        "//src/tango",
        "//src/util",
    ],
)

rust_bindgen(
    name = "src/generated",
    bindgen_flags = [
        "--blocklist-type",
        "schar|uchar|ushort|uint|ulong",
    ],
    cc_lib = ":wrapper",
    clang_flags = [
        "-std=c17",
    ],
    header = "wrapper.h",
    rustfmt = False,
)

rust_library(
    name = "firedancer-sys",
    srcs = [
        "src/lib.rs",
        ":src/generated",  # required because of rules_rust bug
    ] + glob([
        "src/util/**/*.rs",
    ]),
    compile_data = [":src/generated"],
    edition = "2021",
)
