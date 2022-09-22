load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/tango:__subpackages__"])

fd_cc_library(
    name = "mcache",
    srcs = [
        "fd_mcache.c",
        "fd_mcache_private.h",
    ],
    hdrs = [
        "fd_mcache.h",
    ],
    deps = ["//src/tango:base_lib"],
)

fd_cc_test(
    size = "medium",
    srcs = ["test_mcache.c"],
    deps = ["//src/tango"],
)
