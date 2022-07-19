load("//src/tango:package.bzl", "fd_tango_library", "fd_tango_package", "fd_tango_test")

fd_tango_package()

fd_tango_library(
    name = "cnc",
    srcs = [
        "fd_cnc.c",
    ],
    hdrs = [
        "fd_cnc.h",
    ],
)

fd_tango_test(srcs = ["test_cnc.c"])
