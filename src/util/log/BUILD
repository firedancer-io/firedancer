load("//src/util:package.bzl", "fd_util_library", "fd_util_package", "fd_util_test")

fd_util_package()

fd_util_library(
    name = "log",
    srcs = [
        "fd_log.c",
    ],
    hdrs = [
        "fd_log.h",
    ],
    deps = [
        "//src/util/bits",
        "//src/util/env",
    ],
)

fd_util_test(srcs = ["test_log.c"])
