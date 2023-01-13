"""
Defines project wide flags.
"""

# base: Always enabled flags
copts_base = [
    "-Werror",
    "-Wall",
    "-Wextra",
    "-Wpedantic",
    "-Wconversion",
    "-Wdouble-promotion",
    "-Wformat-security",
    "-Wstrict-aliasing",
    "-Wimplicit-fallthrough",

    # Disable false positives
    "-Wno-misleading-indentation",
    "-Wno-ignored-attributes",
    "-Wno-overlength-strings",

    # FD_ADDRESS_OF_PACKED_MEMBER hack does not get past Clang
    "-Wno-address-of-packed-member",
]
linkopts_base = []

# dbg: Debug symbols and pretty backtraces
copts_dbg = [
    "-g",
    "-O1",
]
linkopts_dbg = [
    "-rdynamic",
]

# brutality: Aggressive compiler checks
copts_brutality = [
    "-Winline",
    "-Wsuggest-attribute=pure",
    "-Wsuggest-attribute=const",
    "-Wsuggest-attribute=noreturn",
    "-Wsuggest-attribute=format",
]

# hosted: OS environment (threads)
copts_hosted = [
    "-D_XOPEN_SOURCE=700",
    "-DFD_HAS_HOSTED=1",
]

# opt: Optimized builds
copts_opt = [
    "-O3",
    "-ffast-math",
    "-fno-associative-math",
    "-fno-reciprocal-math",
]

# threads: support multi-threading and NUMA-awareness
copts_threads = [
    "-pthread",
    "-DFD_HAS_THREADS=1",
    "-DFD_HAS_ATOMIC=1",
]
linkopts_threads = [
    "-pthread",
]

# x86_64: floats, dynamic stack
copts_x86_64 = [
    "-DFD_HAS_DOUBLE=1",
    "-DFD_HAS_ALLOCA=1",
    "-DFD_HAS_X86=1",
]

# icelake: x86_64 Intel Ice Lake (10th gen)
copts_icelake = [
    "-fomit-frame-pointer",
    "-falign-functions=32",
    "-falign-jumps=32",
    "-falign-labels=32",
    "-falign-loops=32",
    "-march=icelake-server",
    "-mfpmath=sse",
    "-mbranch-cost=5",
    "-DFD_HAS_INT128=1",
    "-DFD_HAS_SSE=1",
    "-DFD_HAS_AVX=1",
]

# --------------------------------
# Final flags
# --------------------------------

# C/C++ flags
def fd_copts():
    return copts_base + select({
        "//src:dbg_build": copts_dbg,
        "//src:opt_build": copts_opt,
        "//conditions:default": [],
    }) + select({
        "//src:brutality": copts_brutality,
        "//conditions:default": [],
    }) + select({
        "@platforms//cpu:x86_64": copts_x86_64,
        "//conditions:default": [],
    }) + select({
        "//bazel/cpu/x86_64:icelake_server": copts_icelake,
        "//conditions:default": [],
    }) + select({
        "//src:has_hosted": copts_hosted,
        "//conditions:default": [],
    }) + select({
        "//src:has_threads": copts_threads,
        "//conditions:default": [],
    })

# Linker flags
def fd_linkopts():
    return select({
        "//src:dbg_build": linkopts_dbg,
        "//conditions:default": [],
    }) + select({
        "//src:has_threads": linkopts_threads,
        "//conditions:default": [],
    })
