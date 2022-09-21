load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_library")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "log",
    srcs = [
        "fd_log.c",
    ],
    hdrs = [
        "fd_log.h",
    ],
    target_compatible_with = select({
        "//src:has_hosted": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    deps = [
        "//src/util/bits",
        "//src/util/env",
    ],
)

# has exit code 1, so shouldn't be an fd_cc_test
fd_cc_binary(
    name = "test_log",
    srcs = ["test_log.c"],
    deps = ["//src/util"],
)
