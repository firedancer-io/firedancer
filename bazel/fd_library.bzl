load("//bazel:copts.bzl", "fd_copts", "fd_linkopts")

def fd_cc_library(
        name,
        srcs = [],
        hdrs = [],
        copts = [],
        linkopts = [],
        visibility = None,
        tags = [],
        deps = [],
        linkstatic = False,
        defines = [],
        textual_hdrs = []):
    native.cc_library(
        name = name,
        srcs = srcs,
        hdrs = hdrs,
        copts = fd_copts() + copts,
        linkopts = fd_linkopts() + linkopts,
        visibility = visibility,
        tags = tags,
        deps = deps,
        linkstatic = linkstatic,
        defines = defines,
        textual_hdrs = textual_hdrs,
    )

def fd_cc_sub_library_macro(
        deps = [],
        visibility = []):
    def rule(**kwargs):
        kwargs["deps"] = deps + kwargs.get("deps", [])
        kwargs["visibility"] = visibility + kwargs.get("visibility", [])
        return fd_cc_library(**kwargs)

    return rule
