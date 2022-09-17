load("//bazel:copts.bzl", "fd_copts", "fd_linkopts")

def fd_cc_binary(
        name,
        srcs = [],
        copts = [],
        linkopts = [],
        visibility = None,
        tags = [],
        deps = [],
        linkstatic = False,
        defines = []):
    native.cc_binary(
        name = name,
        srcs = srcs,
        copts = fd_copts() + copts,
        linkopts = fd_linkopts() + linkopts,
        visibility = visibility,
        tags = tags,
        deps = deps,
        linkstatic = linkstatic,
        defines = defines,
    )
