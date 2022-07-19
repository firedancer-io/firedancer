load("//bazel:fd_build_system.bzl", "fd_cc_module_test_macro", "fd_cc_sub_library_macro")

def fd_tango_package():
    native.package(default_visibility = ["//src/tango:__subpackages__"])

fd_tango_library = fd_cc_sub_library_macro(
    deps = ["//src/tango:base_lib"],
    visibility = ["//src/tango:__subpackages__"],
)

fd_tango_test = fd_cc_module_test_macro(
    deps = ["//src/tango"],
)
