load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//visibility:public"])

fd_cc_library(
    name = "pack",
    srcs = [
        "fd_compute_budget_program.h",
        "fd_est_tbl.h",
        "fd_pack.c",
    ],
    hdrs = [
        "fd_pack.h",
    ],
    deps = [
        "//src/ballet/txn",
        "//src/disco:base_lib",
    ],
)

fd_cc_binary(
    name = "fd_pack_ctl",
    srcs = [
        "fd_pack_ctl.c",
    ],
    deps = [":pack"],
)

fd_cc_test(
    srcs = ["test_compute_budget_program.c"],
    deps = [":pack"],
)

fd_cc_test(
    srcs = ["test_est_tbl.c"],
    deps = [":pack"],
)

fd_cc_test(
    srcs = ["test_pack.c"],
    deps = [":pack"],
)
