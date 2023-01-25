"""
Defines wrapper rules for C/C++.
"""

load("//bazel:copts.bzl", "fd_copts", "fd_linkopts")
load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")

def __cc_blob_helper(name, suffix, files = []):
    """
    Forces the inclusion of arbitrary files into the inputs of dependent C/C++ targets.

    Returns a list of labels that can be included in cc_library.deps.
    """

    helper_name = name + "_" + suffix
    native.cc_library(name = helper_name, textual_hdrs = files)
    return [helper_name]

def __default_kwargs(kwargs, key, default):
    if not key in kwargs:
        kwargs[key] = default

def __enhance_kwargs(kwargs, key, default, fn):
    kwargs[key] = fn(kwargs.get(key, default))

def fd_cc_binary(
        name,
        compile_data = [],
        textual_hdrs = [],
        **kwargs):
    """
    Wraps cc_binary.

    Prepends project-wide copts / linkopts.

    Reference: https://bazel.build/reference/be/c-cpp#cc_binary

    Args:
      name: Name of fuzz target
      textual_hdrs: See cc_library.textual_hdrs
      compile_data: Arbitrary files to include during build
      **kwargs: Passed through to cc_binary
    """

    __enhance_kwargs(kwargs, "copts", [], lambda x: fd_copts() + x)
    __enhance_kwargs(kwargs, "linkopts", [], lambda x: fd_linkopts() + x)

    # Helper to include arbitrary files in build tree
    if len(compile_data) > 0:
        __enhance_kwargs(kwargs, "deps", [], lambda x: x + __cc_blob_helper(name, "compile_data", compile_data))
    if len(textual_hdrs) > 0:
        __enhance_kwargs(kwargs, "deps", [], lambda x: x + __cc_blob_helper(name, "textual_hdrs", textual_hdrs))

    native.cc_binary(name = name, **kwargs)

def fd_cc_fuzz_test(name = None, srcs = [], **kwargs):
    """
    Wraps cc_fuzz_test, which itself wraps cc_test.

    Reference: https://github.com/bazelbuild/rules_fuzzing/blob/master/docs/cc-fuzzing-rules.md#cc_fuzz_test-corpus

    Args:
      name: Name of fuzz target
      srcs: List of sources
      **kwargs: Passed through to cc_fuzz_test
    """

    # Derive name from first source file
    if name == None:
        name = srcs[0].rsplit(".", 1)[0]
    __enhance_kwargs(kwargs, "copts", [], lambda x: fd_copts() + x)
    __enhance_kwargs(kwargs, "linkopts", [], lambda x: fd_linkopts() + x)
    __default_kwargs(kwargs, "target_compatible_with", select({
        "//bazel/compiler:llvm": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }))

    cc_fuzz_test(
        name = name,
        srcs = srcs,
        **kwargs
    )

def fd_cc_library(
        name,
        linkstatic = True,
        compile_data = [],
        **kwargs):
    """
    Wraps cc_library.

    Prepends project-wide copts / linkopts.

    Reference: https://bazel.build/reference/be/c-cpp#cc_library

    Args:
      name: Name of library target
      linkstatic: See cc_library.linkstatic, now defaults to True
      compile_data: Arbitrary files to include during build
      **kwargs: Passed through to cc_library
    """

    __enhance_kwargs(kwargs, "copts", [], lambda x: fd_copts() + x)
    __enhance_kwargs(kwargs, "linkopts", [], lambda x: fd_linkopts() + x)
    __enhance_kwargs(kwargs, "textual_hdrs", [], lambda x: x + compile_data)
    native.cc_library(
        name = name,
        linkstatic = linkstatic,
        **kwargs
    )

def fd_cc_test(
        name = None,
        srcs = [],
        compile_data = [],
        textual_hdrs = [],
        **kwargs):
    """
    Wraps cc_test.

    Prepends project-wide copts / linkopts.
    Defaults target name to stem of first entry in srcs.

    Reference: https://bazel.build/reference/be/c-cpp#cc_test

    Args:
      name: Name of library target
      srcs: C/C++ headers and source files
      textual_hdrs: See cc_library.textual_hdrs
      compile_data: Arbitrary files to include during build
      **kwargs: Passed through to cc_library
    """

    # Derive name from first source file
    if name == None:
        name = srcs[0].rsplit(".", 1)[0]

    __enhance_kwargs(kwargs, "copts", [], lambda x: fd_copts() + x)
    __enhance_kwargs(kwargs, "linkopts", [], lambda x: fd_linkopts() + x)
    __enhance_kwargs(kwargs, "env", {}, lambda x: dict({
        "FD_LOG_PATH": "-",
        "FD_LOG_LEVEL_STDERR": "7",
    }, **x))

    # Helper to include arbitrary files in build tree
    if len(compile_data) > 0:
        __enhance_kwargs(kwargs, "deps", [], lambda x: x + __cc_blob_helper(name, "compile_data", compile_data))
    if len(textual_hdrs) > 0:
        __enhance_kwargs(kwargs, "deps", [], lambda x: x + __cc_blob_helper(name, "textual_hdrs", textual_hdrs))

    native.cc_test(
        name = name,
        srcs = srcs,
        **kwargs
    )
