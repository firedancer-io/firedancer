load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/disco:__subpackages__"])

fd_cc_library(
    name = "dedup",
    srcs = [
        "fd_dedup.c",
    ],
    hdrs = [
        "fd_dedup.h",
    ],
    deps = [
        "//src/disco:base_lib",
    ],
)

fd_cc_binary(
    name = "fd_dedup_tile",
    srcs = [
        "fd_dedup_tile.c",
    ],
    deps = ["//src/disco"],
)

fd_cc_test(
    srcs = ["test_dedup.c"],
    deps = ["//src/disco"],
)
