load("//src/tango:package.bzl", "fd_tango_library", "fd_tango_package", "fd_tango_test")

fd_tango_package()

fd_tango_library(
    name = "fctl",
    srcs = [
        "fd_fctl.c",
    ],
    hdrs = [
        "fd_fctl.h",
    ],
)

fd_tango_test(srcs = ["test_fctl.c"])
