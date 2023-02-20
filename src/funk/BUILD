load("//bazel:fd_build_system.bzl", "fd_cc_library")

package(default_visibility = ["//visibility:public"])

fd_cc_library(
    name = "fd_funk",
    hdrs = [
        "fd_funk.h",
        "fd_map_giant.h",
        "fd_vector.h",
    ],
    srcs = [
        "fd_funk.c",
    ],
    deps = [
        "//src/util",
    ],
    linkstatic = True,
)
