workspace(name = "firedancer")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

################################################################################
# Bazel Skylib                                                                 #
################################################################################

http_archive(
    name = "bazel_skylib",
    sha256 = "f7be3474d42aae265405a592bb7da8e171919d74c16f082a5457840f06054728",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.2.1/bazel-skylib-1.2.1.tar.gz",
        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.2.1/bazel-skylib-1.2.1.tar.gz",
    ],
)

load("@bazel_skylib//:workspace.bzl", "bazel_skylib_workspace")

bazel_skylib_workspace()

################################################################################
# Python                                                                       #
################################################################################

http_archive(
    name = "rules_python",
    sha256 = "497ca47374f48c8b067d786b512ac10a276211810f4a580178ee9b9ad139323a",
    strip_prefix = "rules_python-0.16.1",
    url = "https://github.com/bazelbuild/rules_python/archive/refs/tags/0.16.1.tar.gz",
)

load("@rules_python//python:repositories.bzl", "python_register_toolchains")

python_register_toolchains(
    name = "python3_10",
    python_version = "3.10",
)

################################################################################
# Foreign C/C++ build systems                                                  #
################################################################################

http_archive(
    name = "rules_foreign_cc",
    sha256 = "2a4d07cd64b0719b39a7c12218a3e507672b82a97b98c6a89d38565894cf7c51",
    strip_prefix = "rules_foreign_cc-0.9.0",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/refs/tags/0.9.0.tar.gz",
)

load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")

rules_foreign_cc_dependencies()

################################################################################
# Fuzzing                                                                      #
################################################################################

http_archive(
    name = "rules_fuzzing",
    sha256 = "d9002dd3cd6437017f08593124fdd1b13b3473c7b929ceb0e60d317cb9346118",
    strip_prefix = "rules_fuzzing-0.3.2",
    urls = ["https://github.com/bazelbuild/rules_fuzzing/archive/v0.3.2.zip"],
)

load("@rules_fuzzing//fuzzing:repositories.bzl", "rules_fuzzing_dependencies")

rules_fuzzing_dependencies()

load("@python3_10//:defs.bzl", python_interpreter = "interpreter")
load("@rules_python//python:pip.bzl", "pip_parse")

pip_parse(
    name = "fuzzing_py_deps",
    extra_pip_args = ["--require-hashes"],
    python_interpreter_target = python_interpreter,
    requirements_lock = "@rules_fuzzing//fuzzing:requirements.txt",
)

load("@fuzzing_py_deps//:requirements.bzl", install_python_fuzzing_deps = "install_deps")

install_python_fuzzing_deps()

################################################################################
# GNU Compiler Collection                                                      #
################################################################################

# Import GCC toolchain.
http_archive(
    name = "aspect_gcc_toolchain",
    sha256 = "dd07660d9a28a6be19eac90a992f5a971a3db6c9d0a52814f111e41aea5afba4",
    strip_prefix = "gcc-toolchain-0.4.2",
    urls = ["https://github.com/aspect-build/gcc-toolchain/archive/refs/tags/0.4.2.zip"],
)

load("@aspect_gcc_toolchain//toolchain:repositories.bzl", "gcc_toolchain_dependencies")
load("@aspect_gcc_toolchain//toolchain:defs.bzl", "gcc_register_toolchain")

gcc_toolchain_dependencies()

# GCC 11.3.0
gcc_register_toolchain(
    name = "gcc11_x86-64-v2",
    sha256 = "4313a04996173bd79935ffaec48b97ba7c32332880774ec61b40ab76804b8fbb",
    strip_prefix = "x86-64-v2--glibc--stable-2022.08-1",
    target_arch = "x86_64",
    target_compatible_with = ["@//bazel/compiler:gcc"],
    url = "https://toolchains.bootlin.com/downloads/releases/toolchains/x86-64-v2/tarballs/x86-64-v2--glibc--stable-2022.08-1.tar.bz2",
)

################################################################################
# LLVM                                                                         #
################################################################################

http_archive(
    name = "grail_llvm_toolchain",
    sha256 = "06e1421091f153029c070f1ae364f8cb5a61dab20ede97a844a0f7bfcec632a4",
    strip_prefix = "bazel-toolchain-0.8",
    url = "https://github.com/grailbio/bazel-toolchain/archive/refs/tags/0.8.zip",
)

# LLVM 14.0.0
load("@grail_llvm_toolchain//toolchain:rules.bzl", "llvm_toolchain")

llvm_toolchain(
    name = "llvm14",
    llvm_version = "14.0.0",
)

register_toolchains("//bazel/toolchains:x86_64_linux_llvm")

################################################################################
# Core C dependencies                                                          #
################################################################################

http_archive(
    name = "numa",
    build_file = "@//:third_party/numa.BUILD",
    sha256 = "1508bb02f56f1b9376243980ba96291856ba083e7a3480fdcb0fbf11ff01d6fa",
    strip_prefix = "numactl-2.0.15",
    url = "https://github.com/numactl/numactl/archive/refs/tags/v2.0.15.tar.gz",
)

################################################################################
# Rust                                                                         #
################################################################################

http_archive(
    name = "rules_rust",
    sha256 = "aaaa4b9591a5dad8d8907ae2dbe6e0eb49e6314946ce4c7149241648e56a1277",
    urls = ["https://github.com/bazelbuild/rules_rust/releases/download/0.16.1/rules_rust-v0.16.1.tar.gz"],
)

load("@rules_rust//rust:repositories.bzl", "rules_rust_dependencies", "rust_register_toolchains")

rules_rust_dependencies()

rust_register_toolchains()

load("@rules_rust//bindgen:repositories.bzl", "rust_bindgen_dependencies", "rust_bindgen_register_toolchains")

rust_bindgen_dependencies()

rust_bindgen_register_toolchains()

################################################################################
# Wireshark plugin dependencies (optional)                                     #
################################################################################

# Fetch Wireshark
http_archive(
    name = "wireshark",
    build_file = "//:third_party/wireshark.BUILD",
    sha256 = "425c0454734dfb74ac3b384689a3c9c99077fbce2b52b9794165b9cc965d8301",
    strip_prefix = "wireshark-v4.0.2",
    url = "https://gitlab.com/wireshark/wireshark/-/archive/v4.0.2/wireshark-v4.0.2.tar.gz",
)
