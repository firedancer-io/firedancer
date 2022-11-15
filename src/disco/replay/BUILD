load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/disco:__subpackages__"])

fd_cc_library(
    name = "replay",
    srcs = [
        "fd_replay.c",
    ],
    hdrs = [
        "fd_replay.h",
    ],
    deps = [
        "//src/disco:base_lib",
    ],
)

fd_cc_binary(
    name = "fd_replay_tile",
    srcs = [
        "fd_replay_tile.c",
    ],
    deps = ["//src/disco"],
)

fd_cc_test(
    srcs = ["test_replay.c"],
    tags = ["manual"],
    deps = ["//src/disco"],
)
