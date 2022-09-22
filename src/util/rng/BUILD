load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "rng",
    srcs = [
        "fd_rng.c",
    ],
    hdrs = [
        "fd_rng.h",
    ],
    deps = [
        "//src/util/bits",
    ],
)

fd_cc_test(
    size = "large",
    srcs = ["test_rng.c"],
    deps = ["//src/util"],
)
