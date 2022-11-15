load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_library")

package(default_visibility = ["//visibility:public"])

fd_cc_library(
    name = "frank",
    hdrs = [
        "fd_frank.h",
    ],
    visibility = ["//visibility:private"],
    deps = [
        "//src/ballet",
        "//src/disco",
    ],
)

fd_cc_binary(
    name = "fd_frank_main",
    srcs = [
        "fd_frank.h",
        "fd_frank_dedup.c",
        "fd_frank_main.c",
        "fd_frank_pack.c",
        "fd_frank_verify.c",
    ],
    deps = [":frank"],
)

fd_cc_binary(
    name = "fd_frank_mon.bin",
    srcs = [
        "fd_frank_mon.bin.c",
    ],
    deps = [":frank"],
)
