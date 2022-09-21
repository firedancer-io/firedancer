load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_library", "fd_cc_test")

fd_cc_library(
    name = "base_lib",
    hdrs = [
        "fd_tango.h",
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
    linkstatic = True,
    visibility = ["//visibility:public"],
    deps = [
        ":base_lib",
        "//src/tango/cnc",
        "//src/tango/dcache",
        "//src/tango/fctl",
        "//src/tango/fseq",
        "//src/tango/mcache",
        "//src/tango/tcache",
        "//src/tango/tempo",
    ],
)

fd_cc_binary(
    name = "fd_tango_ctl",
    srcs = ["fd_tango_ctl.c"],
    visibility = ["//visibility:public"],
    deps = [":tango"],
)

fd_cc_test(
    srcs = ["test_tango_base.c"],
    deps = ["//src/tango"],
    size = "medium",
)

fd_cc_binary(
    name = "bench_frag_tx",
    srcs = ["bench_frag_tx.c"],
    visibility = ["//visibility:public"],
    deps = [":tango"],
)

fd_cc_test(
    srcs = ["test_frag_rx.c"],
    deps = ["//src/tango"],
    size = "small",
)

fd_cc_test(
    srcs = ["test_frag_tx.c"],
    deps = ["//src/tango"],
    size = "small",
)

fd_cc_test(
    srcs = ["test_meta_rx.c"],
    deps = ["//src/tango"],
    size = "small",
)

fd_cc_test(
    srcs = ["test_meta_tx.c"],
    deps = ["//src/tango"],
    size = "small",
)
