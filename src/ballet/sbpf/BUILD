load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//visibility:public"])

fd_cc_library(
    name = "sbpf",
    hdrs = ["fd_sbpf_opcode.h"],
)

fd_cc_library(
    name = "loader",
    srcs = ["fd_sbpf_loader.c"],
    hdrs = ["fd_sbpf_loader.h"],
    deps = [
        ":sbpf",
        "//src/util",
    ],
)

fd_cc_test(
    size = "small",
    srcs = ["test_sbpf_opcode.c"],
    deps = [
        ":sbpf",
        "//src/util",
    ],
)

fd_cc_binary(
    name = "test_sbpf_loader",
    srcs = ["test_sbpf_loader.c"],
    deps = [
        ":loader",
        "//src/util",
    ],
)
