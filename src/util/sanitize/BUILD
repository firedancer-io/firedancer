load("//bazel:fd_build_system.bzl", "fd_cc_library")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "sanitize",
    hdrs = [
        "fd_asan.h",
        "fd_sanitize.h",
    ],
    deps = [
        "//src/util:base_lib",
    ],
)
