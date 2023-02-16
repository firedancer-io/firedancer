load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_library")

fd_cc_library(
    name = "xdp",
    srcs = [
        "fd_xdp.c",
        "fd_xdp_fs.c",
    ],
    hdrs = [
        "fd_xdp.h",
        "fd_xdp_private.h",
        "fd_xdp_ring_defs.h",
    ],
    deps = [
        "//src/util",
        "@libbpf",
    ],
)

fd_cc_binary(
    name = "fd_quic_attach",
    srcs = ["fd_quic_attach.c"],
    deps = [":xdp"],
)

fd_cc_binary(
    name = "fd_quic_detach",
    srcs = ["fd_quic_detach.c"],
    deps = [":xdp"],
)
