load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/tango:__subpackages__"])

fd_cc_library(
    name = "cnc",
    srcs = [
        "fd_cnc.c",
    ],
    hdrs = [
        "fd_cnc.h",
    ],
    deps = ["//src/tango:base_lib"],
)

# requires custom tile amount
fd_cc_test(
    srcs = ["test_cnc.c"],
    tags = ["manual"],
    deps = ["//src/tango"],
)
