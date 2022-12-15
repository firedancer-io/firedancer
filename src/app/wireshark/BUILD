load("//bazel:fd_build_system.bzl", "fd_cc_binary")

fd_cc_binary(
    name = "libsolana_dissectors.so",
    srcs = ["packet_turbine.c"],
    linkshared = True,  # produce shared library
    linkstatic = True,  # statically link user libraries
    visibility = ["//visibility:public"],
    deps = [
        "//src/ballet",
        "//src/util",
        "@wireshark//:includes",
    ],
)
