load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//visibility:public"])

fd_cc_library(
    name = "runtime",
    srcs = [
        "fd_banks_solana.c",
        "fd_rocksdb.c",
    ],
    hdrs = [
        "fd_banks_solana.h",
        "fd_global_state.h",
        "fd_rocksdb.h",
    ],
    copts = ["-DFD_HAS_ROCKSDB=1"],
    deps = [
        "//src/ballet:base_lib",
        "//src/ballet/shred",
        "//src/util/encoders",
    ],
)

fd_cc_test(
    size = "small",
    srcs = ["test_runtime.c"],
    copts = ["-DFD_HAS_ROCKSDB=1"],
    deps = [
        ":runtime",
        "//src/ballet",
        "//src/funk:fd_funk",
        "@rocksdb",
    ],
)
