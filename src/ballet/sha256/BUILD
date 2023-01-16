load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

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

# Required because textual_hdrs is not available in cc_test.
fd_cc_library(
    name = "test_sha256_static",
    textual_hdrs = [
        "fd_sha256_test_vector.c",
    ],
)

fd_cc_test(
    size = "medium",
    srcs = ["test_sha256.c"],
    deps = [
        ":test_sha256_static",
        "//src/ballet",
    ],
)
