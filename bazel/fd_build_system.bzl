"""
Defines wrapper rules for C/C++.
"""

load("//bazel:copts.bzl", "fd_copts", "fd_linkopts")
load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")

def fd_cc_binary(
        name,
        copts = [],
        linkopts = [],
        **kwargs):
    """
    Wraps cc_binary.

    Prepends project-wide copts / linkopts.

    Reference: https://bazel.build/reference/be/c-cpp#cc_binary
    """

    native.cc_binary(
        name = name,
        copts = fd_copts() + copts,
        linkopts = fd_linkopts() + linkopts,
        **kwargs
    )

def fd_cc_fuzz_test(
        name = None,
        srcs = [],
        copts = [],
        linkopts = [],
        target_compatible_with = None,
        **kwargs):
    """
    Wraps cc_fuzz_test, which itself wraps cc_test.

    Reference: https://github.com/bazelbuild/rules_fuzzing/blob/master/docs/cc-fuzzing-rules.md#cc_fuzz_test-corpus

    Args:
      name: Name of fuzz target
      srcs: List of sources
      copts: Additional copts flags (plus project_wide flags)
      linkopts: Additional linkopts flags (plus project wide flags)
      target_compatible_with: Target constraints, defaults to LLVM-only
      **kwargs: Passed through to cc_fuzz_test
    """

    # Derive name from first source file
    if name == None:
        name = srcs[0].rsplit(".", 1)[0]
    if target_compatible_with == None:
        target_compatible_with = select({
            "//bazel/compiler:llvm": [],
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
    """
    Wraps cc_library.

    Prepends project-wide copts / linkopts.

    Reference: https://bazel.build/reference/be/c-cpp#cc_library
    """

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
        env = {},
        **kwargs):
    """
    Wraps cc_test.

    Prepends project-wide copts / linkopts.
    Defaults target name to stem of first entry in srcs.

    Reference: https://bazel.build/reference/be/c-cpp#cc_test
    """

    # Derive name from first source file
    if name == None:
        name = srcs[0].rsplit(".", 1)[0]
    native.cc_test(
        name = name,
        srcs = srcs,
        copts = fd_copts() + copts,
        linkopts = fd_linkopts() + linkopts,
        env = dict({
            "FD_LOG_PATH": "-",
        }, **env),
        **kwargs
    )
