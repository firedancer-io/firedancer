load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//visibility:public"])

fd_cc_library(
    name = "base_lib",
    hdrs = [
        "fd_disco.h",
        "fd_disco_base.h",
    ],
    linkstatic = True,
    visibility = [":__subpackages__"],
    deps = ["//src/tango"],
)

fd_cc_library(
    name = "disco",
    linkstatic = True,
    deps = [
        ":base_lib",
        "//src/disco/dedup",
        "//src/disco/mux",
        "//src/disco/replay",
    ],
)

fd_cc_test(
    srcs = ["test_disco_base.c"],
    deps = [":disco"],
)
