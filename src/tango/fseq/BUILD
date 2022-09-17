load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/tango:__subpackages__"])

fd_cc_library(
    name = "fseq",
    srcs = [
        "fd_fseq.c",
    ],
    hdrs = [
        "fd_fseq.h",
    ],
    deps = ["//src/tango:base_lib"],
)

fd_cc_test(
    srcs = ["test_fseq.c"],
    deps = ["//src/tango"],
)
