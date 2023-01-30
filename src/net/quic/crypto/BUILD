load("//bazel:fd_build_system.bzl", "fd_cc_library")

fd_cc_library(
    name = "crypto",
    srcs = glob(["fd_*.c"]),
    hdrs = glob(["fd_*.h"]),
    visibility = ["//src/net/quic:__subpackages__"],
    deps = [
        "//src/net/quic:base_lib",
        "//src/net/quic/templ",
        "//src/net/quic/tls",
    ],
)
