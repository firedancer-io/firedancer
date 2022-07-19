load("//src/util:package.bzl", "fd_util_library", "fd_util_package", "fd_util_test")

fd_util_package()

fd_util_library(
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

fd_util_test(srcs = ["test_map_dynamic.c"])

fd_util_test(srcs = ["test_map.c"])

fd_util_test(srcs = ["test_prq.c"])

fd_util_test(srcs = ["test_set_dynamic.c"])

fd_util_test(srcs = ["test_set.c"])

fd_util_test(srcs = ["test_smallset.c"])

fd_util_test(srcs = ["test_sort.c"])
