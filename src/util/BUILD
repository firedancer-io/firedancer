load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "base_lib",
    srcs = [
        "fd_hash.c",
    ],
    hdrs = [
        "fd_util_base.h",
    ],
    linkstatic = True,
)

fd_cc_library(
    name = "util",
    srcs = [
        "fd_util.c",
    ],
    hdrs = [
        "fd_util.h",
    ],
    linkstatic = True,
    visibility = ["//visibility:public"],
    deps = [
        "base_lib",
        "//src/util/bits",
        "//src/util/cstr",
        "//src/util/env",
        "//src/util/log",
        "//src/util/math",
        "//src/util/net",
        "//src/util/pod",
        "//src/util/rng",
        "//src/util/scratch",
        "//src/util/shmem",
        "//src/util/tile",
        "//src/util/wksp",
    ],
)

fd_cc_test(
    size = "medium",
    srcs = ["test_util_base.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_util.c"],
    deps = ["//src/util"],
)
