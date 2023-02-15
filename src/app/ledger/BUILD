load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//visibility:public"])

fd_cc_library(
    name = "ledger",
    srcs = [
        "fd_funk.c",
    ],
    hdrs = [
        "fd_funk.h",
        "fd_map_giant.h",
        "fd_vector.h",
    ],
    deps = [
        "//src/ballet",
    ],
)

fd_cc_test(
    srcs = ["test_funk.cxx"],
    copts = ["-std=c++17"],
    deps = [":ledger"],
)
