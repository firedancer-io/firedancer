cc_library(
    name = "includes",
    hdrs = glob(["**/*.h"]),
    includes = [
        ".",
        "include",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "@//third_party/wireshark_gen:includes",
        "@glib_includes",
    ],
)
