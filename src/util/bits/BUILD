load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "bits",
    hdrs = [
        "fd_bits.h",
        "fd_bits_find_lsb.h",
        "fd_bits_find_msb.h",
        "fd_float.h",
        "fd_uwide.h",
    ],
    deps = ["//src/util:base_lib"],
)

fd_cc_test(
    srcs = ["test_bits.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    srcs = ["test_float.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    srcs = ["test_hash.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    srcs = ["test_uwide.c"],
    deps = ["//src/util"],
)
