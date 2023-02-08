load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/ballet:__subpackages__"])

fd_cc_library(
    name = "txn",
    srcs = [
        "fd_txn_parse.c",
    ],
    hdrs = [
        "fd_compact_u16.h",
        "fd_txn.h",
    ],
    deps = [
        "//src/ballet:base_lib",
        "//src/ballet/ed25519",
    ],
)

fd_cc_test(
    size = "medium",
    srcs = ["test_compact_u16.c"],
    copts = ["-O3"],
    deps = ["//src/ballet"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_txn_parse.c"],
    deps = ["//src/ballet"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_txn.c"],
    deps = ["//src/ballet"],
)
