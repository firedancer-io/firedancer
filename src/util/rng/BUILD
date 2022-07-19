load("//src/util:package.bzl", "fd_util_library", "fd_util_package", "fd_util_test")

fd_util_package()

fd_util_library(
    name = "rng",
    srcs = [
        "fd_rng.c",
    ],
    hdrs = [
        "fd_rng.h",
    ],
    deps = [
        "//src/util/bits",
    ],
)

fd_util_test(srcs = ["test_rng.c"])
