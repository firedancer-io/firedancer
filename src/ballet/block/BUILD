load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/ballet:__subpackages__"])

fd_cc_library(
    name = "block",
    srcs = [
        "fd_microblock.c",
    ],
    hdrs = [
        "fd_microblock.h",
    ],
    deps = [
        "//src/ballet:base_lib",
        "//src/ballet/bmtree",
        "//src/ballet/sha256",
        "//src/ballet/txn",
    ],
)

fd_cc_test(
    srcs = ["test_microblock.c"],
    compile_data = [
        "//src/ballet/shred:fixtures/localnet-slot0-batch0.bin",
        "//src/ballet/shred:fixtures/localnet-slot210-batch6.bin",
    ],
    deps = ["//src/ballet"],
)
