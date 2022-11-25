load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/ballet:__subpackages__"])

fd_cc_library(
    name = "shred",
    srcs = [
        "fd_shred.c",
    ],
    hdrs = [
        "fd_shred.h",
    ],
    deps = [
        "//src/ballet:base_lib",
    ],
)

fd_cc_test(
    srcs = ["test_shred.c"],
    deps = [
        "//src/ballet",
    ],
)
