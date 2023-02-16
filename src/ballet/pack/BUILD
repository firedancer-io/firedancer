load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/ballet:__subpackages__"])

fd_cc_library(
    name = "pack",
    srcs = ["fd_pack.c"],
    hdrs = [
        "fd_compute_budget_program.h",
        "fd_est_tbl.h",
        "fd_pack.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//src/ballet:base_lib",
        "//src/ballet/bmtree",
        "//src/ballet/ed25519",
        "//src/ballet/poh",
        "//src/ballet/shred",
        "//src/ballet/txn",
        "//src/tango",
    ],
)

fd_cc_binary(
    name = "fd_pack_ctl",
    srcs = ["fd_pack_ctl.c"],
    visibility = ["//visibility:public"],
    deps = [
        ":pack",
        "//src/ballet",
    ],
)

fd_cc_test(
    size = "small",
    srcs = ["test_est_tbl.c"],
    deps = ["//src/ballet"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_compute_budget_program.c"],
    deps = ["//src/ballet"],
)
