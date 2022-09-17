load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "math",
    srcs = [
        "fd_stat.c",
    ],
    hdrs = [
        "fd_fxp.h",
        "fd_sqrt.h",
        "fd_stat.h",
    ],
    deps = [
        "//src/util/bits",
        "//src/util/tmpl",
    ],
)

fd_cc_test(
    srcs = ["test_fxp.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    srcs = ["test_sqrt.c"],
    deps = ["//src/util"],
)
