load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/ballet:__subpackages__"])

exports_files(glob(["fixtures/*"]))

fd_cc_library(
    name = "shred",
    srcs = [
        "fd_shred.c",
    ],
    hdrs = [
        "fd_shred.h",
    ],
    deps = [
        "//src/ballet:base_lib",
        "//src/ballet/block",
    ],
)

fd_cc_test(
    srcs = ["test_shred.c"],
    deps = ["//src/ballet"],
)

fd_cc_test(
    srcs = ["test_deshredder.c"],
    compile_data = [
        "fixtures/localnet-slot0-shreds.ar",
        "fixtures/localnet-slot0-batch0.bin",
    ],
    deps = ["//src/ballet"],
)
