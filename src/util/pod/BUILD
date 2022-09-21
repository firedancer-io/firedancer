load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "pod",
    srcs = [
        "fd_pod.c",
    ],
    hdrs = [
        "fd_pod.h",
    ],
    deps = [
        "//src/util/bits",
        "//src/util/cstr",
    ],
)

fd_cc_binary(
    name = "fd_pod_ctl",
    srcs = ["fd_pod_ctl.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    srcs = ["test_pod.c"],
    deps = ["//src/util"],
)
