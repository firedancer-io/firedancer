load("//bazel:fd_build_system.bzl", "fd_cc_fuzz_test", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//visibility:public"])

fd_cc_library(
    name = "csv",
    srcs = [
        "fd_csv.c",
        "fd_csv_private.h",
    ],
    hdrs = ["fd_csv.h"],
    deps = [
        "//src/util:base_lib",
        "//src/util/bits",
        "//src/util/cstr",
        "//src/util/sanitize",
    ],
)

fd_cc_test(
    name = "test_csv",
    srcs = [
        "fd_csv_private.h",
        "test_csv.c",
    ],
    deps = [
        ":csv",
        "//src/util",
    ],
)

fd_cc_fuzz_test(
    name = "fuzz_csv",
    srcs = ["fuzz_csv.c"],
    deps = [
        ":csv",
        "//src/util",
    ],
)
