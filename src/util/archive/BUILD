load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "archive",
    srcs = [
        "fd_ar.c",
    ],
    hdrs = [
        "fd_ar.h",
    ],
    deps = ["//src/util:base_lib"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_ar.c"],
    compile_data = ["//src/ballet/shred:fixtures/localnet-shreds-0.ar"],
    deps = ["//src/util"],
)
