load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")
<<<<<<< PATCH SET (f52b67 sha256: add test program and CAVP test vectors)
load("//:contrib/cavp_generate.bzl", "cc_generate_cavp_test_vector")
=======
>>>>>>> BASE      (9e7fc9 rm CONTRIBUTE.md)

package(default_visibility = ["//src/ballet:__subpackages__"])

fd_cc_library(
    name = "sha256",
    srcs = [
        "fd_sha256.c",
    ],
    hdrs = [
        "fd_sha256.h",
    ],
    deps = [
        "//src/ballet:base_lib",
    ],
)

<<<<<<< PATCH SET (f52b67 sha256: add test program and CAVP test vectors)
cc_generate_cavp_test_vector(
    name = "cavp/sha256_short.inc",
    algorithm = "sha256",
    id = "cavp_sha256_short",
    response_file = ":cavp/SHA256ShortMsg.rsp",
)

cc_generate_cavp_test_vector(
    name = "cavp/sha256_long.inc",
    algorithm = "sha256",
    id = "cavp_sha256_long",
    response_file = ":cavp/SHA256LongMsg.rsp",
)

fd_cc_test(
    srcs = ["test_sha256.c"],
    local_defines = ["HAS_CAVP_TEST_VECTORS"],
    deps = [
        ":cavp/sha256_long.inc",
        ":cavp/sha256_short.inc",
=======
# Required because textual_hdrs is not available in cc_test.
fd_cc_library(
    name = "test_sha256_static",
    textual_hdrs = [
        "fd_sha256_test_vector.c",
    ],
)

fd_cc_test(
    size = "medium",
    srcs = ["test_sha256.c"],
    deps = [
        ":test_sha256_static",
>>>>>>> BASE      (9e7fc9 rm CONTRIBUTE.md)
        "//src/ballet",
    ],
)
