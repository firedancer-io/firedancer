load("//src/tango:package.bzl", "fd_tango_library", "fd_tango_package", "fd_tango_test")

fd_tango_package()

fd_tango_library(
    name = "dcache",
    srcs = [
        "fd_dcache.c",
        "fd_dcache_private.h",
    ],
    hdrs = [
        "fd_dcache.h",
    ],
)

fd_tango_test(srcs = ["test_dcache.c"])
