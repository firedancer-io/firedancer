load("//bazel:copts.bzl", "fd_copts", "fd_linkopts")
load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")

def fd_package():
    native.package(default_visibility = ["//visibility:public"])

def fd_cc_binary(
        name,
        copts = [],
        linkopts = [],
        **kwargs):
    native.cc_binary(
        name = name,
        copts = fd_copts() + copts,
        linkopts = fd_linkopts() + linkopts,
        **kwargs
    )

# fd_cc_fuzz_test reference:
# https://github.com/bazelbuild/rules_fuzzing/blob/master/docs/cc-fuzzing-rules.md#cc_fuzz_test-corpus
# https://bazel.build/reference/be/c-cpp#cc_test
def fd_cc_fuzz_test(
        name = None,
        srcs = [],
        copts = [],
        linkopts = [],
        target_compatible_with = None,
        **kwargs):
    # Derive name from first source file
    if name == None:
        name = srcs[0].rsplit(".", 1)[0]
    if target_compatible_with == None:
        target_compatible_with = select({
            "//bazel/compiler:clang": [],
            "//conditions:default": ["@platforms//:incompatible"],
        })
    cc_fuzz_test(
        name = name,
        srcs = srcs,
        copts = fd_copts() + copts,
        linkopts = fd_linkopts() + linkopts,
        target_compatible_with = target_compatible_with,
        **kwargs
    )

def fd_cc_library(
        name,
        copts = [],
        linkopts = [],
        **kwargs):
    native.cc_library(
        name = name,
        copts = fd_copts() + copts,
        linkopts = fd_linkopts() + linkopts,
        **kwargs
    )

def fd_cc_test(
        name = None,
        srcs = [],
        copts = [],
        linkopts = [],
        **kwargs):
    # Derive name from first source file
    if name == None:
        name = srcs[0].rsplit(".", 1)[0]
    native.cc_test(
        name = name,
        srcs = srcs,
        copts = fd_copts() + copts,
        linkopts = fd_linkopts() + linkopts,
        **kwargs
    )
