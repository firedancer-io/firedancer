load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_library", "fd_cc_test")
load(":package.bzl", "fd_tango_test")

fd_cc_library(
    name = "base_lib",
    hdrs = [
        "fd_tango_base.h",
    ],
    linkstatic = True,
    visibility = [":__subpackages__"],
    deps = [
        "//src/util",
    ],
)

fd_cc_library(
    name = "tango",
    hdrs = [
        "fd_tango.h",
    ],
    linkstatic = True,
    visibility = ["//visibility:public"],
    deps = [
        ":base_lib",
        "//src/tango/cnc",
        "//src/tango/dcache",
        "//src/tango/fctl",
        "//src/tango/fseq",
        "//src/tango/mcache",
    ],
)

fd_cc_binary(
    name = "fd_tango_ctl",
    srcs = [
        "fd_tango_ctl.c",
    ],
    visibility = ["//visibility:public"],
    deps = [
        ":tango",
    ],
)

fd_tango_test(srcs = ["test_tango_base.c"])

fd_tango_test(srcs = ["test_meta_rx.c"])

fd_tango_test(srcs = ["test_meta_tx.c"])
