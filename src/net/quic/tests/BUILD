load("//bazel:fd_build_system.bzl", "fd_cc_test")

fd_cc_test(
    size = "small",
    srcs = ["test_checksum.c"],
    deps = ["//src/net/quic"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_crypto.c"],
    deps = ["//src/net/quic"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_frames.c"],
    deps = ["//src/net/quic"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_handshake.c"],
    deps = ["//src/net/quic"],
)

fd_cc_test(
    name = "test_quic_hs",
    size = "small",
    srcs = [
        "fd_pcap.h",
        "test_quic_hs.c",
    ],
    deps = ["//src/net/quic"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_tls_decrypt.c"],
    deps = ["//src/net/quic"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_tls_pcap.c"],
    deps = ["//src/net/quic"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_tls_pcap2.c"],
    deps = ["//src/net/quic"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_tls_quic_both.c"],
    deps = ["//src/net/quic"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_tls.c"],
    deps = ["//src/net/quic"],
)
