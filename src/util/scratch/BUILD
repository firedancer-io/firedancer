load("//src/util:package.bzl", "fd_util_library", "fd_util_package", "fd_util_test")

fd_util_package()

fd_util_library(
    name = "scratch",
    srcs = [
        "fd_scratch.c",
    ],
    hdrs = [
        "fd_scratch.h",
    ],
    deps = [
        "//src/util/log",
    ],
)

fd_util_test(srcs = ["test_scratch.c"])
