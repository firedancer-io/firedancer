load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

configure_make(
    name = "openssl",
    configure_command = "config",
    configure_in_place = True,
    # Provide the minimal set of features required for QUIC.
    configure_options = [
        "enable-quic",
        "no-comp",
        "no-dsa",
        "no-idea",
        "no-weak-ssl-ciphers",
    ],
    lib_source = ":all_srcs",
    # Although we link OpenSSL statically,
    # these static libraries still dynamically link system libraries.
    linkopts = [
        "-pthread",
        "-ldl",
    ],
    out_static_libs = [
        "libssl.a",
        "libcrypto.a",
    ],
    visibility = ["//visibility:public"],
)
