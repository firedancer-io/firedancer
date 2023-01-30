load("//bazel:fd_build_system.bzl", "fd_cc_library")

fd_cc_library(
    name = "base_lib",
    hdrs = ["fd_net.h"],
    linkstatic = True,
    visibility = ["//visibility:public"],
    deps = [
        "//src/util",
    ],
)
