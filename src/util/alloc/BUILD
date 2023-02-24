load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "alloc",
    srcs = [
        "fd_alloc.c",
    ],
    hdrs = [
        "fd_alloc.h",
        "fd_alloc_cfg.h",
    ],
    deps = [
        "//src/util:base_lib",
        "//src/util/wksp",
    ],
)

fd_cc_test(
    size = "small",
    srcs = ["test_alloc.c"],
    deps = ["//src/util"],
)
