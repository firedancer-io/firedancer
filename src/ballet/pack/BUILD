load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

fd_cc_library(
    name = "pack",
    hdrs = [
        "fd_compute_budget_program.h",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//src/ballet:base_lib",
    ],
)

fd_cc_test(
    size = "small",
    srcs = ["test_compute_budget_program.c"],
    deps = ["//src/ballet"],
)
