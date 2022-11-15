load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_library")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "wksp",
    srcs = [
        "fd_wksp.c",
        "fd_wksp_pod.c",
    ],
    hdrs = [
        "fd_wksp.h",
        "fd_wksp_private.h",
    ],
    deps = [
        "//src/util/pod",
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

fd_cc_binary(
    name = "test_wksp",
    srcs = ["test_wksp.c"],
    deps = ["//src/util"],
)
