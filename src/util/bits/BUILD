load("//src/util:package.bzl", "fd_util_library", "fd_util_package", "fd_util_test")

fd_util_package()

fd_util_library(
    name = "bits",
    hdrs = [
        "fd_bits.h",
        "fd_bits_find_lsb.h",
        "fd_bits_find_msb.h",
        "fd_float.h",
        "fd_uwide.h",
    ],
)

fd_util_test(srcs = ["test_bits.c"])

fd_util_test(srcs = ["test_float.c"])

fd_util_test(srcs = ["test_hash.c"])

fd_util_test(srcs = ["test_uwide.c"])
