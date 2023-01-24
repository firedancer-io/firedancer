load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "shmem",
    srcs = [
        "fd_shmem_admin.c",
        "fd_shmem_user.c",
    ] + select({
        "@platforms//os:linux": ["fd_numa_linux.inc"],
        "@platforms//os:macos": ["fd_numa_darwin.inc"],
        "//conditions:default": ["fd_numa_stub.inc"],
    }),
    hdrs = [
        "fd_shmem.h",
        "fd_shmem_private.h",
    ],
    deps = [
        "//src/util:base_lib",
        "//src/util/cstr",
        "//src/util/env",
        "//src/util/log",
        "//src/util/tmpl",
    ],
)

fd_cc_binary(
    name = "fd_shmem_ctl",
    srcs = ["fd_shmem_ctl.c"],
    deps = ["//src/util"],
)

# requires privileges
fd_cc_test(
    srcs = ["test_shmem.c"],
    tags = ["manual"],
    deps = ["//src/util"],
)

fd_cc_test(
    name = "test_numa",
    srcs = ["test_numa.c"] + select({
        "@platforms//os:linux": ["test_numa_linux.inc"],
        "//conditions:default": [],
    }),
    deps = ["//src/util"],
)
