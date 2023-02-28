load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "tile",
    srcs = select({
        "//src:has_threads": ["fd_tile_threads.cxx"],
        "//conditions:default": ["fd_tile_nothreads.cxx"],
    }),
    hdrs = [
        "fd_tile.h",
    ],
    copts = ["-std=c++17"],
    deps = [
        "//src/util/shmem",
    ],
)

fd_cc_test(
    size = "small",
    srcs = ["test_tile.c"],
    deps = ["//src/util"],
)
