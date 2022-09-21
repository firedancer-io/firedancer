load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/tango:__subpackages__"])

fd_cc_library(
    name = "tempo",
    srcs = ["fd_tempo.c"],
    hdrs = ["fd_tempo.h"],
    deps = [
        "//src/tango:base_lib",
        "//src/tango/cnc",
        "//src/tango/dcache",
        "//src/tango/fctl",
        "//src/tango/fseq",
        "//src/tango/mcache",
        "//src/tango/tcache",
    ],
)

fd_cc_test(
    srcs = ["test_tempo.c"],
    deps = ["//src/tango"],
    size = "small",
)
