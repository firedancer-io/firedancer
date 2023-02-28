load("//bazel:fd_build_system.bzl", "fd_cc_library")

fd_cc_library(
    name = "base_lib",
    hdrs = glob(["*.h"]),
    visibility = [":__subpackages__"],
    deps = [
        "//src/net/aio",
    ],
)

fd_cc_library(
    name = "quic",
    srcs = glob(["*.c"]),
    visibility = ["//visibility:public"],
    deps = [
        "//src/net:base_lib",
        "//src/net/quic/crypto",
        "//src/net/quic/templ",
        "//src/net/quic/tls",
        "//src/net/util",
        "//src/util",
    ],
)
