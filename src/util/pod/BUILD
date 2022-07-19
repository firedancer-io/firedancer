load("//src/util:package.bzl", "fd_util_library", "fd_util_package", "fd_util_test")

fd_util_package()

fd_util_library(
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

fd_util_test(srcs = ["test_pod.c"])
