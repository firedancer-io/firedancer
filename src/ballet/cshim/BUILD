load("//bazel:fd_build_system.bzl", "fd_cc_library")

package(default_visibility = ["//src/ballet:__subpackages__"])

fd_cc_library(
    name = "cshim",
    srcs = [
        "fd_cshim_chan.c",
        "fd_cshim_pack_return.c",
        "fd_cshim_verify_feeder.c",
    ],
    hdrs = [
        "fd_cshim.h",
        "fd_cshim_chan.h",
        "fd_cshim_tile.h",
    ],
    deps = [
        "//src/ballet:base_lib",
        "//src/util",
    ],
)
