load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/ballet:__subpackages__"])

fd_cc_library(
    name = "ed25519",
    srcs = [
        "fd_ed25519_fe.c",
        "fd_ed25519_ge.c",
        "fd_ed25519_user.c",
    ],
    hdrs = [
        "fd_ed25519.h",
        "fd_ed25519_private.h",
    ],
    textual_hdrs = [
        "avx/fd_ed25519_fe_avx_inl.h",
        "avx/fd_ed25519_fe_avx.h",
        "avx/fd_ed25519_fe.c",
        "avx/fd_ed25519_fe.h",
        "avx/fd_ed25519_ge.c",
        "ref/fd_ed25519_fe.c",
        "ref/fd_ed25519_fe.h",
        "ref/fd_ed25519_ge.c",
        "table/fd_ed25519_ge_bi_precomp_avx.c",
        "table/fd_ed25519_ge_bi_precomp.c",
        "table/fd_ed25519_ge_k25519_precomp.c",
    ],
    deps = [
        "//src/ballet:base_lib",
        "//src/ballet/sha512",
    ],
)

fd_cc_test(
    srcs = ["test_ed25519.c"],
    deps = ["//src/ballet"],
)
