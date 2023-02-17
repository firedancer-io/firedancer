load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

filegroup(
    name = "srcs",
    srcs = glob(["**"]),
)

cmake(
    name = "rocksdb",
    build_args = ["--parallel `njobs`"],
    cache_entries = {
        "ROCKSDB_BUILD_SHARED": "OFF",
        "WITH_BZ2": "ON",
        "WITH_SNAPPY": "ON",
        "WITH_ZLIB": "ON",
        "WITH_ZSTD": "ON",
        "WITH_GFLAGS": "OFF",
        "WITH_ALL_TESTS": "OFF",
        "WITH_BENCHMARK_TOOLS": "OFF",
        "WITH_CORE_TOOLS": "OFF",
        "WITH_RUNTIME_DEBUG": "OFF",
        "WITH_TESTS": "OFF",
        "WITH_TOOLS": "OFF",
        "WITH_TRACE_TOOLS": "OFF",
    },
    generate_args = ["-G Ninja"],
    lib_source = "//:srcs",
    linkopts = [
        "-lz",
        "-lbz2",
        "-lsnappy",
        "-lzstd",
    ],
    out_lib_dir = "lib64",
    out_static_libs = ["librocksdb.a"],
    visibility = ["//visibility:public"],
)
