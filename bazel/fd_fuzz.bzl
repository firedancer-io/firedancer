load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")
load("//bazel:copts.bzl", "fd_copts", "fd_linkopts")

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
            "//bazel:clang": [],
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
