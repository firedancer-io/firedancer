load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_fuzz_test", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "net",
    srcs = [
        "fd_eth.c",
        "fd_pcap.c",
    ],
    hdrs = [
        "fd_eth.h",
        "fd_igmp.h",
        "fd_ip4.h",
        "fd_pcap.h",
        "fd_udp.h",
    ],
    deps = [
        "//src/util/bits",
        "//src/util/log",
    ],
)

fd_cc_test(
    size = "small",
    srcs = ["test_eth.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_igmp.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_ip4.c"],
    deps = ["//src/util"],
)

fd_cc_binary(
    name = "test_pcap",
    srcs = ["test_pcap.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    srcs = ["test_udp.c"],
    deps = ["//src/util"],
)

fd_cc_fuzz_test(
    srcs = ["fuzz_pcap.c"],
    deps = ["//src/util"],
)
