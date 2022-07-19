load("//src/util:package.bzl", "fd_util_library", "fd_util_package", "fd_util_test")

fd_util_package()

fd_util_library(
    name = "env",
    srcs = [
        "fd_env.c",
    ],
    hdrs = [
        "fd_env.h",
    ],
    deps = [
        "//src/util/cstr",
    ],
)

fd_util_test(srcs = ["test_env.c"])
