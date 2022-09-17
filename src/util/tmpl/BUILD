load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//src/util:__subpackages__"])

fd_cc_library(
    name = "tmpl",
    textual_hdrs = [
        "fd_map.c",
        "fd_map_dynamic.c",
        "fd_prq.c",
        "fd_set.c",
        "fd_set_dynamic.c",
        "fd_smallset.c",
        "fd_sort.c",
    ],
)

fd_cc_test(
    srcs = ["test_map_dynamic.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    srcs = ["test_map.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    srcs = ["test_prq.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    srcs = ["test_set_dynamic.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    srcs = ["test_set.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    srcs = ["test_smallset.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    srcs = ["test_sort.c"],
    deps = ["//src/util"],
)
