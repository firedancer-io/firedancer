load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/ballet:__subpackages__"])

fd_cc_library(
    name = "base58",
    srcs = [
        "fd_base58.c",
        "fd_base58_avx.h",
    ],
    hdrs = ["fd_base58.h"],
    textual_hdrs = [
        "fd_base58_tmpl.c",
    ],
    deps = [
        "//src/ballet:base_lib",
        "//src/util/simd",
    ],
)

fd_cc_test(
    size = "medium",
    srcs = ["test_base58.c"],
    args = [
        "--cnt",
        "10000",
    ],
    deps = [
        "//src/ballet/base58",
        "//src/util",
    ],
)
