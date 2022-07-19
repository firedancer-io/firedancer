load("//src/util:package.bzl", "fd_util_library", "fd_util_package", "fd_util_test")
load("//bazel:fd_build_system.bzl", "fd_cc_binary")

fd_util_package()

fd_util_library(
    name = "wksp",
    srcs = [
        "fd_wksp.c",
    ],
    hdrs = [
        "fd_wksp.h",
        "fd_wksp_private.h",
    ],
    deps = [
        "//src/util/shmem",
    ],
)

fd_cc_binary(
    name = "fd_wksp_ctl",
    srcs = [
        "fd_wksp_ctl.c",
    ],
    deps = ["//src/util"],
)

fd_util_test(srcs = ["test_wksp.c"])
