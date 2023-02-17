load("//bazel:fd_build_system.bzl", "fd_cc_binary")

package(default_visibility = ["//visibility:public"])

fd_cc_binary(
    name = "ledger",
    srcs = [
        "main.c",
        "tar.c",
        "tar.h",
        "tar_impl.h",
    ],
    linkopts = ["-lzstd"],
    deps = [
        "//src/ballet",
        "//src/ballet/runtime",
        "//src/util",
    ],
)
