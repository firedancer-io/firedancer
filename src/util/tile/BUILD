load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "tile",
    srcs = [
        "fd_tile.cxx",
    ],
    hdrs = [
        "fd_tile.h",
    ],
    textual_hdrs = select({
        "//bazel:nothreads": ["fd_tile_nothreads.cxx"],
        "//conditions:default": ["fd_tile_threads.cxx"],
    }),
    deps = [
        "//src/util/shmem",
    ],
)

fd_cc_test(
    srcs = ["test_tile.c"],
    deps = ["//src/util"],
)
