# --------------------------------
# Flag definitions
# --------------------------------

# with-debug
debug_cppflags = [
    "-g",
]
debug_ldflags = [
    "-rdynamic",
]

# with-brutality
brutality_cppflags = [
    "-Werror",
    "-Wall",
    "-Wextra",
    "-Wpedantic",
    "-Wstrict-aliasing=2",
    "-Wimplicit-fallthrough=2",
    "-Wconversion",
    "-Wdouble-promotion",
]
brutality_extra_cppflags = [
    "-Winline",
    "-Wsuggest-attribute=pure",
    "-Wsuggest-attribute=const",
    "-Wsuggest-attribute=noreturn",
    "-Wsuggest-attribute=format",
]

# with-hosted
hosted_cppflags = [
    "-D_XOPEN_SOURCE=700",
    "-DFD_HAS_HOSTED=1",
]

# with-optimization
optimization_cppflags = [
    "-O3",
    "-ffast-math",
    "-fno-associative-math",
    "-fno-reciprocal-math",
]

# with-threads
threads_cppflags = [
    "-pthread",
    "-DFD_HAS_THREADS=1",
    "-DFD_HAS_ATOMIC=1",
]
threads_ldflags = [
    "-pthread",
]

# Base x86 flags
x86_64_cppflags = [
    "-DFD_HAS_DOUBLE=1",
    "-DFD_HAS_ALLOCA=1",
    "-DFD_HAS_X86=1",
]

# Intel Ice Lake (10th gen)
icelake_server_cppflags = [
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

darwin_cppflags = [
    "-D_DARWIN_C_SOURCE=1",
    "-DFD_HAS_INT128=1",
    "-DFD_HAS_SSE=1",
    "-DFD_HAS_AVX=1",
]

# --------------------------------
# Final flags
# --------------------------------

# C/C++ flags
def fd_copts():
    return [
        "-Wno-misleading-indentation",
        "-Wno-ignored-attributes",
    ] + select({
        "//bazel:dbg_build": debug_cppflags,
        "//bazel:opt_build": optimization_cppflags,
        "//conditions:default": [],
    }) + select({
        "//bazel:brutality": brutality_cppflags,
        "//conditions:default": [],
    }) + select({
        "@platforms//cpu:x86_64": x86_64_cppflags,
        "//conditions:default": [],
    }) + select({
        "//bazel:machine_icelake": icelake_server_cppflags,
        "//conditions:default": [],
    }) + select({
        "@platforms//os:macos": darwin_cppflags,
        "//conditions:default": [],
    }) + select({
        "//bazel:nothreads": [],
        "//conditions:default": threads_cppflags,
    }) + hosted_cppflags

# Linker flags
def fd_linkopts():
    return [
        "-lnuma",
    ] + select({
        "//bazel:dbg_build": debug_ldflags,
        "//conditions:default": [],
    }) + threads_ldflags
