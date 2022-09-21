load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/tango:__subpackages__"])

fd_cc_library(
    name = "fctl",
    srcs = [
        "fd_fctl.c",
    ],
    hdrs = [
        "fd_fctl.h",
    ],
    deps = ["//src/tango:base_lib"],
)

fd_cc_test(
    srcs = ["test_fctl.c"],
    deps = ["//src/tango"],
    size = "small",
)
