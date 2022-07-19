load("//src/tango:package.bzl", "fd_tango_library", "fd_tango_package", "fd_tango_test")

fd_tango_package()

fd_tango_library(
    name = "fseq",
    srcs = [
        "fd_fseq.c",
    ],
    hdrs = [
        "fd_fseq.h",
    ],
)

fd_tango_test(srcs = ["test_fseq.c"])
