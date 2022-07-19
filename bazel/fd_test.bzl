load("//bazel:copts.bzl", "fd_copts", "fd_linkopts")

def fd_cc_test(
        name = None,
        srcs = [],
        data = [],
        copts = [],
        linkopts = [],
        deps = [],
        tags = [],
        args = [],
        env = {}):
    # Derive name from first source file
    if name == None:
        name = srcs[0].rsplit(".", 1)[0]
    native.cc_test(
        name = name,
        srcs = srcs,
        data = data,
        copts = fd_copts() + copts,
        linkopts = fd_linkopts() + linkopts,
        deps = deps,
        tags = tags,
        args = args,
        env = env,
    )

def fd_cc_module_test_macro(deps = []):
    def rule(**kwargs):
        kwargs["deps"] = deps + kwargs.get("deps", [])
        return fd_cc_test(**kwargs)

    return rule
