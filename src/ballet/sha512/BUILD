load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/ballet:__subpackages__"])

fd_cc_library(
    name = "sha512",
    srcs = [
        "fd_sha512.c",
        "fd_sha512_core_avx2.S",
    ],
    hdrs = [
        "fd_sha512.h",
    ],
    deps = [
        "//src/ballet:base_lib",
    ],
)

# Required because textual_hdrs is not available in cc_test.
fd_cc_library(
    name = "test_sha512_static",
    textual_hdrs = [
        "fd_sha512_test_vector.c",
    ],
)

fd_cc_test(
    srcs = ["test_sha512.c"],
    deps = [
        ":test_sha512_static",
        "//src/ballet",
    ],
)
