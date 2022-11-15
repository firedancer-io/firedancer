load("//bazel:fd_build_system.bzl", "fd_cc_library", "fd_cc_test")

package(default_visibility = ["//visibility:public"])

fd_cc_library(
    name = "simd",
    hdrs = [
        "fd_avx.h",
        "fd_avx_wc.h",
        "fd_avx_wd.h",
        "fd_avx_wf.h",
        "fd_avx_wi.h",
        "fd_avx_wl.h",
        "fd_sse.h",
        "fd_sse_vc.h",
        "fd_sse_vd.h",
        "fd_sse_vf.h",
        "fd_sse_vi.h",
        "fd_sse_vl.h",
    ],
)

fd_cc_test(
    srcs = ["test_avx.c"],
    deps = ["//src/util"],
)

fd_cc_test(
    srcs = ["test_sse.c"],
    deps = ["//src/util"],
)
