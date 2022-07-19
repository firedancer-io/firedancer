load("//bazel:fd_build_system.bzl", "fd_cc_binary")
load("//src/util:package.bzl", "fd_util_library", "fd_util_package", "fd_util_test")

fd_util_package()

fd_util_library(
    name = "shmem",
    srcs = [
        "fd_shmem_admin.c",
        "fd_shmem_user.c",
    ],
    hdrs = [
        "fd_shmem.h",
        "fd_shmem_private.h",
    ],
    deps = [
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

fd_util_test(srcs = ["test_shmem.c"])
