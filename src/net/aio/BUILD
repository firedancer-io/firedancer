load("//bazel:fd_build_system.bzl", "fd_cc_library")

fd_cc_library(
    name = "aio",
    srcs = glob(["fd_*.c"]),
    hdrs = glob(["fd_*.h"]),
    visibility = ["//visibility:public"],
    deps = [
        "//src/util",
    ],
)
