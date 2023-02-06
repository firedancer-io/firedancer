load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//visibility:public"])

fd_cc_library(
    name = "sbpf",
    hdrs = [
        "fd_opcode.h",
        "fd_sbpf.h",
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
