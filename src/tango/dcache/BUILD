load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/tango:__subpackages__"])

fd_cc_library(
    name = "dcache",
    srcs = [
        "fd_dcache.c",
        "fd_dcache_private.h",
    ],
    hdrs = [
        "fd_dcache.h",
    ],
    deps = ["//src/tango:base_lib"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_dcache.c"],
    deps = ["//src/tango"],
)
