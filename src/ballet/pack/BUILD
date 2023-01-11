load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test", "fd_cc_binary")

package(default_visibility = ["//src/ballet:__subpackages__"])

fd_cc_library(
    name = "pack",
    srcs = [ "fd_pack.c" ],
    hdrs = [
        "fd_pack.h",
        "fd_compute_budget_program.h",
        "fd_est_tbl.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//src/tango",
        "//src/ballet/txn",
        "//src/ballet/ed25519",
        "//src/ballet/poh",
        "//src/ballet/shred",
        "//src/ballet/bmtree",
        "//src/ballet:base_lib",
    ],
)

fd_cc_binary(
    name = "fd_pack_ctl",
    srcs = ["fd_pack_ctl.c"],
    visibility = ["//visibility:public"],
    deps = [":pack"],
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
