load("//bazel:fd_build_system.bzl", "fd_cc_module_test_macro", "fd_cc_sub_library_macro")

def fd_util_package():
    native.package(default_visibility = ["//src/util:__subpackages__"])

fd_util_library = fd_cc_sub_library_macro(
    deps = ["//src/util:base_lib"],
    visibility = ["//src/util:__subpackages__"],
)

fd_util_test = fd_cc_module_test_macro(
    deps = ["//src/util"],
)
