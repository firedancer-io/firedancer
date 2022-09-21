load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_library")

package(default_visibility = ["//src/tango:__subpackages__"])

fd_cc_library(
    name = "tcache",
    srcs = ["fd_tcache.c"],
    hdrs = ["fd_tcache.h"],
    deps = ["//src/tango:base_lib"],
)

fd_cc_binary(
    name = "test_tcache",
    srcs = ["test_tcache.c"],
    deps = ["//src/tango"],
)
