load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/tango:__subpackages__"])

fd_cc_library(
    name = "tcache",
    srcs = ["fd_tcache.c"],
    hdrs = ["fd_tcache.h"],
    deps = ["//src/tango:base_lib"],
)

fd_cc_test(
    name = "test_tcache",
    srcs = ["test_tcache.c"],
    tags = ["manual"],  # requires superuser
    deps = ["//src/tango"],
)
