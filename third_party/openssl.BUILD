load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

configure_make(
    name = "openssl",
    configure_command = "config",
    configure_in_place = True,
    configure_options = [
        "no-comp",
        "no-idea",
        "no-weak-ssl-ciphers",
        "no-shared",
    ],
    lib_source = ":all_srcs",
    out_static_libs = [
        "libssl.a",
        "libcrypto.a",
    ],
    visibility = ["//visibility:public"],
)
