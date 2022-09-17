load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "log",
    srcs = [
        "fd_log.c",
    ],
    hdrs = [
        "fd_log.h",
    ],
    deps = [
        "//src/util/bits",
        "//src/util/env",
    ],
)

fd_cc_test(
    srcs = ["test_log.c"],
    deps = ["//src/util"],
)
