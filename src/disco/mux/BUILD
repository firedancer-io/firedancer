load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/disco:__subpackages__"])

fd_cc_library(
    name = "mux",
    srcs = [
        "fd_mux.c",
    ],
    hdrs = [
        "fd_mux.h",
    ],
    deps = [
        "//src/disco:base_lib",
    ],
)

fd_cc_binary(
    name = "fd_mux_tile",
    srcs = [
        "fd_mux_tile.c",
    ],
    deps = ["//src/disco"],
)

fd_cc_test(
    srcs = ["test_mux.c"],
    deps = ["//src/disco"],
)
