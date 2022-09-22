load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "env",
    srcs = [
        "fd_env.c",
    ],
    hdrs = [
        "fd_env.h",
    ],
    deps = [
        "//src/util/cstr",
    ],
)

fd_cc_test(
    size = "small",
    srcs = ["test_env.c"],
    deps = ["//src/util"],
)
