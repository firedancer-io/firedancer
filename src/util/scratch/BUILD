load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "scratch",
    srcs = [
        "fd_scratch.c",
    ],
    hdrs = [
        "fd_scratch.h",
    ],
    deps = [
        "//src/util/log",
    ],
)

fd_cc_test(
    srcs = ["test_scratch.c"],
    deps = ["//src/util"],
    size = "small",
)
