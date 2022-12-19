load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")
load("//:contrib/cavp_generate.bzl", "cc_generate_cavp_test_vector")

package(default_visibility = ["//src/ballet:__subpackages__"])

fd_cc_library(
    name = "sha512",
    srcs = [
        "fd_sha512.c",
        "fd_sha512_core_avx2.S",
    ],
    hdrs = [
        "fd_sha512.h",
    ],
    deps = [
        "//src/ballet:base_lib",
    ],
)

# Required because textual_hdrs is not available in cc_test.
fd_cc_library(
    name = "test_sha512_static",
    textual_hdrs = [
        "fd_sha512_test_vector.c",
    ],
)

cc_generate_cavp_test_vector(
    name = "cavp/sha512_short.inc",
    algorithm = "sha512",
    id = "cavp_sha512_short",
    response_file = ":cavp/SHA512ShortMsg.rsp",
)

cc_generate_cavp_test_vector(
    name = "cavp/sha512_long.inc",
    algorithm = "sha512",
    id = "cavp_sha512_long",
    response_file = ":cavp/SHA512LongMsg.rsp",
)

fd_cc_test(
    srcs = ["test_sha512.c"],
    local_defines = ["HAS_CAVP_TEST_VECTORS"],
    deps = [
        ":cavp/sha512_long.inc",
        ":cavp/sha512_short.inc",
        ":test_sha512_static",
        "//src/ballet",
    ],
)
