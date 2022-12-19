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
        "fd_deque.c",
        "fd_deque_dynamic.c",
    ],
)

fd_cc_test(
    size = "small",
    srcs = ["test_map_dynamic.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_map.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_prq.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    size = "medium",
    srcs = ["test_set_dynamic.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    size = "medium",
    srcs = ["test_set.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_smallset.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    size = "medium",
    srcs = ["test_sort.c"],
    deps = ["//src/util"],
)
fd_cc_test(
    size = "small",
    srcs = ["test_deque_dynamic.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    size = "small",
    srcs = ["test_deque.c"],
    deps = ["//src/util"],
)
