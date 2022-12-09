load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/ballet:__subpackages__"])

fd_cc_library(
    name = "bmtree",
    srcs = [
        "fd_bmtree.c",
        "fd_bmtree.inc",
    ],
    hdrs = [
        "fd_bmtree.h",
    ],
    deps = [
        "//src/ballet:base_lib",
        "//src/ballet/sha256",
    ],
)

fd_cc_test(
    size = "small",
    srcs = ["test_bmtree20.c"],
    deps = ["//src/ballet"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_bmtree32.c"],
    deps = ["//src/ballet"],
)
