load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/ballet:__subpackages__"])

fd_cc_library(
    name = "base58",
    hdrs = [
        "fd_base58.h",
    ],
    deps = [
        "//src/ballet:base_lib",
    ],
)

fd_cc_test(
    size = "small",
    srcs = ["test_base58.c"],
    deps = ["//src/ballet"],
)

