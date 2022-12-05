workspace(name = "firedancer")

# Bazel system loads
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Common useful functions and rules for Bazel
http_archive(
    name = "bazel_skylib",
    sha256 = "f7be3474d42aae265405a592bb7da8e171919d74c16f082a5457840f06054728",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.2.1/bazel-skylib-1.2.1.tar.gz",
        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.2.1/bazel-skylib-1.2.1.tar.gz",
    ],
)

# Bazel dependency loads
load("@bazel_skylib//:workspace.bzl", "bazel_skylib_workspace")

bazel_skylib_workspace()

# libFuzzer support
http_archive(
    name = "rules_fuzzing",
    sha256 = "d9002dd3cd6437017f08593124fdd1b13b3473c7b929ceb0e60d317cb9346118",
    strip_prefix = "rules_fuzzing-0.3.2",
    urls = ["https://github.com/bazelbuild/rules_fuzzing/archive/v0.3.2.zip"],
)

load("@rules_fuzzing//fuzzing:repositories.bzl", "rules_fuzzing_dependencies")

rules_fuzzing_dependencies()

load("@rules_fuzzing//fuzzing:init.bzl", "rules_fuzzing_init")

rules_fuzzing_init()

# Foreign C/C++ support
http_archive(
    name = "rules_foreign_cc",
    sha256 = "2a4d07cd64b0719b39a7c12218a3e507672b82a97b98c6a89d38565894cf7c51",
    strip_prefix = "rules_foreign_cc-0.9.0",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/refs/tags/0.9.0.tar.gz",
)

load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")

rules_foreign_cc_dependencies()

# Rustc support
http_archive(
    name = "rules_rust",
    sha256 = "0cc7e6b39e492710b819e00d48f2210ae626b717a3ab96e048c43ab57e61d204",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_rust/releases/download/0.10.0/rules_rust-v0.10.0.tar.gz",
        "https://github.com/bazelbuild/rules_rust/releases/download/0.10.0/rules_rust-v0.10.0.tar.gz",
    ],
)

load("@rules_rust//rust:repositories.bzl", "rules_rust_dependencies", "rust_register_toolchains")

rules_rust_dependencies()

# Make sure to keep this synced to Solana upstream.
# See: ./labs/solana/ci/rust-version.sh
rust_register_toolchains(
    edition = "2021",
    version = "1.63.0",
)

# Import cargo-raze generated crate targets.
load("//labs/cargo:crates.bzl", "raze_fetch_remote_crates")

raze_fetch_remote_crates()

# Define Solana as source-only repository.
new_local_repository(
    name = "solana",
    build_file = "./third_party/solana.BUILD",
    path = "./third_party/solana",
)

# Import GCC toolchain.
http_archive(
    name = "aspect_gcc_toolchain",
    sha256 = "dd07660d9a28a6be19eac90a992f5a971a3db6c9d0a52814f111e41aea5afba4",
    strip_prefix = "gcc-toolchain-0.4.2",
    urls = ["https://github.com/aspect-build/gcc-toolchain/archive/refs/tags/0.4.2.zip"],
)

load("@aspect_gcc_toolchain//toolchain:repositories.bzl", "gcc_toolchain_dependencies")

gcc_toolchain_dependencies()

load("@aspect_gcc_toolchain//toolchain:defs.bzl", "gcc_register_toolchain")

# GCC 11.3.0
gcc_register_toolchain(
    name = "gcc11_x86-64-v2",
    sha256 = "4313a04996173bd79935ffaec48b97ba7c32332880774ec61b40ab76804b8fbb",
    strip_prefix = "x86-64-v2--glibc--stable-2022.08-1",
    target_arch = "x86_64",
    target_compatible_with = ["@//bazel/compiler:gcc"],
    url = "https://toolchains.bootlin.com/downloads/releases/toolchains/x86-64-v2/tarballs/x86-64-v2--glibc--stable-2022.08-1.tar.bz2",
)

# Import LLVM toolchain.
http_archive(
    name = "grail_llvm_toolchain",
    sha256 = "7fa5a8624b1148c36e09c7fa29ef6ee8b83f865219c9c219c9125aac78924758",
    strip_prefix = "bazel-toolchain-c3131a6894804ee586d059c57ffe8e88d44172e1",
    # version 0.7.2 plus fixes, including support for RHEL.
    url = "https://github.com/grailbio/bazel-toolchain/archive/c3131a6894804ee586d059c57ffe8e88d44172e1.zip",
)

# LLVM 14.0.0
load("@grail_llvm_toolchain//toolchain:rules.bzl", "llvm_toolchain")

llvm_toolchain(
    name = "llvm14",
    llvm_version = "14.0.0",
)

register_toolchains("//bazel/toolchains:x86_64_linux_llvm")

# Fetch libnuma
http_archive(
    name = "numa",
    build_file = "@//:third_party/numa.BUILD",
    sha256 = "1508bb02f56f1b9376243980ba96291856ba083e7a3480fdcb0fbf11ff01d6fa",
    strip_prefix = "numactl-2.0.15",
    url = "https://github.com/numactl/numactl/archive/refs/tags/v2.0.15.tar.gz",
)

################################################################################
# Wireshark plugin dependencies (optional)                                     #
################################################################################

# Source GLib headers from local distribution.
#
# We generally try to avoid sourcing local files, as those break deterministic builds.
# However, GLib uses the Meson/Ninja build system which we cannot easily import from Bazel.
#
# GLib is currently only used for Wireshark support, making this workaround acceptable.
new_local_repository(
    name = "glib_includes",
    build_file_content = """
cc_library(
    name = "glib_includes",
    hdrs = glob(["**/*.h"]),
    includes = ["."],
    visibility = ["//visibility:public"],
    deps = ["@glib_lib64_config"],
)
""",
    path = "/usr/include/glib-2.0",
)

# Ancillary repo for the system-specific GLib header.
# It simply exports the "/usr/lib64/glib-2.0/include/glibconfig.h" as a system include.
new_local_repository(
    name = "glib_lib64_config",
    build_file_content = """
cc_library(
    name = "glib_lib64_config",
    hdrs = ["glibconfig.h"],
    includes = ["."],
    visibility = ["//visibility:public"],
)
""",
    path = "/usr/lib64/glib-2.0/include",
)

# Fetch Wireshark headers
http_archive(
    name = "wireshark",
    build_file_content = """
cc_library(
    name = "includes",
    hdrs = glob(["**/*.h"]),
    includes = ["."],
    visibility = ["//visibility:public"],
    deps = ["@glib_includes"],
)
""",
    sha256 = "d499d050fdd7f3d55238d63610ffa87df2a52d8c3f1c84cb181f6f79f836e9a2",
    strip_prefix = "wireshark-v3.6.9",
    url = "https://gitlab.com/wireshark/wireshark/-/archive/v3.6.9/wireshark-v3.6.9.tar.gz",
)
