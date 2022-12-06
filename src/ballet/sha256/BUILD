load("//bazel:fd_build_system.bzl", "fd_cc_library")

package(default_visibility = ["//src/ballet:__subpackages__"])

fd_cc_library(
    name = "sha256",
    srcs = [
        "fd_sha256.c",
    ],
    hdrs = [
        "fd_sha256.h",
    ],
    deps = [
        "//src/ballet:base_lib",
    ],
)
