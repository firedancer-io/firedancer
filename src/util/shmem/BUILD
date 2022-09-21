load("//bazel:fd_build_system.bzl", "fd_cc_binary", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
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

# requires privileges
fd_cc_test(
    srcs = ["test_shmem.c"],
    deps = ["//src/util"],
    tags = ["manual"],
)
