load("//src/util:package.bzl", "fd_util_library", "fd_util_package", "fd_util_test")

fd_util_package()

fd_util_library(
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

fd_util_test(srcs = ["test_tile.c"])
