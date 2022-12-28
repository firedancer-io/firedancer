load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/ballet:__subpackages__"])

fd_cc_library(
    name = "poh",
    srcs = [
        "fd_poh.c",
    ],
    hdrs = [
        "fd_poh.h",
    ],
    deps = [
        "//src/ballet:base_lib",
        "//src/ballet/sha256",
    ],
)

fd_cc_test(
    size = "small",
    srcs = ["test_poh.c"],
    deps = ["//src/ballet"],
)
