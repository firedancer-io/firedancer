load("@rules_foreign_cc//foreign_cc:configure.bzl", "configure_make")

filegroup(
    name = "srcs",
    srcs = glob([
        "m4/*.m4",
        "*.h",
        "*.c",
    ]) + [
        "autogen.sh",
        "configure.ac",
        "Makefile.am",
        "versions.ldscript",
    ],
)

# Header-only build.
# All targets in firedancer except //src/util:util should depend on this.
configure_make(
    name = "libnuma_headers",
    autogen = True,
    configure_in_place = True,
    configure_options = [
        "--disable-shared",
        "--enable-static",
    ],
    lib_source = "//:srcs",
    out_headers_only = True,
    targets = [
        "install-includeHEADERS",
    ],
    visibility = ["//visibility:public"],
)

# Statically linked build of libnuma.
configure_make(
    name = "libnuma",
    autogen = True,
    configure_in_place = True,
    configure_options = [
        "--disable-shared",
        "--enable-static",
    ],
    lib_source = "//:srcs",
    targets = [
        "libnuma.la",
        "install-includeHEADERS",
        "install-libLTLIBRARIES",
    ],
    visibility = ["//visibility:public"],
)

# Alias for convenience: bazel build @numa
alias(
    name = "numa",
    actual = ":libnuma",
    visibility = ["//visibility:public"],
)
