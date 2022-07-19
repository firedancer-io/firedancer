load("//src/util:package.bzl", "fd_util_library", "fd_util_package", "fd_util_test")

fd_util_package()

fd_util_library(
    name = "cstr",
    srcs = [
        "fd_cstr.c",
    ],
    hdrs = [
        "fd_cstr.h",
    ],
    deps = [
        "//src/util/bits",
    ],
)

fd_util_test(srcs = ["test_cstr.c"])
