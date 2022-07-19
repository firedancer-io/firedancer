load("//src/tango:package.bzl", "fd_tango_library", "fd_tango_package", "fd_tango_test")

fd_tango_package()

fd_tango_library(
    name = "mcache",
    srcs = [
        "fd_mcache.c",
        "fd_mcache_private.h",
    ],
    hdrs = [
        "fd_mcache.h",
    ],
)

fd_tango_test(srcs = ["test_mcache.c"])
