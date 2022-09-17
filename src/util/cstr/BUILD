load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "cstr",
    srcs = [
        "fd_cstr.c",
    ],
    hdrs = [
        "fd_cstr.h",
    ],
    deps = [
        "//src/util/bits",
    ],
)

fd_cc_test(
    srcs = ["test_cstr.c"],
    deps = ["//src/util"],
)
