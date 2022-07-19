load("//src/util:package.bzl", "fd_util_library", "fd_util_package", "fd_util_test")

fd_util_package()

fd_util_library(
    name = "net",
    srcs = [
        "fd_eth.c",
    ],
    hdrs = [
        "fd_eth.h",
        "fd_igmp.h",
        "fd_ip4.h",
        "fd_udp.h",
    ],
    deps = [
        "//src/util/bits",
    ],
)

fd_util_test(srcs = ["test_eth.c"])

fd_util_test(srcs = ["test_igmp.c"])

fd_util_test(srcs = ["test_ip4.c"])

fd_util_test(srcs = ["test_udp.c"])
