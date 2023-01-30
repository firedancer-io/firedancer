load("@//bazel:includes.bzl", "prepare_include_dir")

includes = [
    "src/bpf.h",
    "src/bpf_core_read.h",
    "src/bpf_endian.h",
    "src/bpf_helper_defs.h",
    "src/bpf_helpers.h",
    "src/bpf_tracing.h",
    "src/btf.h",
    "src/libbpf.h",
    "src/libbpf_common.h",
    "src/libbpf_legacy.h",
    "src/libbpf_version.h",
    "src/skel_internal.h",
    "src/usdt.bpf.h",
]

cc_library(
    name = "bpf",
    srcs = [
        "src/bpf.c",
        "src/bpf_gen_internal.h",
        "src/bpf_prog_linfo.c",
        "src/btf.c",
        "src/btf_dump.c",
        "src/gen_loader.c",
        "src/hashmap.c",
        "src/hashmap.h",
        "src/libbpf.c",
        "src/libbpf_errno.c",
        "src/libbpf_internal.h",
        "src/libbpf_probes.c",
        "src/linker.c",
        "src/netlink.c",
        "src/nlattr.c",
        "src/nlattr.h",
        "src/relo_core.c",
        "src/relo_core.h",
        "src/ringbuf.c",
        "src/str_error.c",
        "src/str_error.h",
        "src/strset.c",
        "src/strset.h",
        "src/usdt.c",
    ],
    hdrs = includes + glob([
        "include/**/*.h",
    ]),
    copts = [
        "-Werror",
        "-Wall",
        "-std=gnu89",
        "-D_LARGEFILE_SOURCE",
        "-D_FILE_OFFSET_BITS=64",
        "-isystem",
        "external/libbpf/include",
        "-isystem",
        "external/libbpf/include/uapi",
    ],
    defines = [
        "FD_HAS_LIBBPF=1",
    ],
    linkopts = [
        "-lelf",
        "-lz",
    ],
    visibility = ["//visibility:public"],
)

# Create fake "include" dir for dependent libraries.
#
# This is required to make files appear under the include prefix "bpf",
# e.g. `#include <bpf/bpf.h>`.
include_dir_files = prepare_include_dir(
    headers = includes,
    prefix = "include/bpf",
    strip_prefix = "src",
    visibility = ["//visibility:public"],
)

cc_library(
    name = "libbpf",
    hdrs = include_dir_files,
    includes = ["include"],
    visibility = ["//visibility:public"],
    deps = [":bpf"],
)
