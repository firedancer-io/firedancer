load("//src/util:package.bzl", "fd_util_library", "fd_util_package", "fd_util_test")

fd_util_package()

fd_util_library(
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

fd_util_test(srcs = ["test_fxp.c"])

fd_util_test(srcs = ["test_sqrt.c"])
