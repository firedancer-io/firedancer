load("@bazel_skylib//rules:common_settings.bzl", "bool_flag")

package(default_visibility = ["//visibility:public"])

# --------------------------------
# Platforms
# --------------------------------

platform(
    name = "linux_x86_64_gcc",
    constraint_values = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
        "//bazel/compiler:gcc",
    ],
)

platform(
    name = "linux_x86_64_llvm",
    constraint_values = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
        "//bazel/compiler:llvm",
    ],
)

# --------------------------------
# Flags
# --------------------------------

bool_flag(
    name = "brutality",
    build_setting_default = False,
)

bool_flag(
    name = "dbg",
    build_setting_default = False,
)

bool_flag(
    name = "hosted",
    build_setting_default = True,
)

bool_flag(
    name = "threads",
    build_setting_default = True,
)

# --------------------------------
# Tools
# --------------------------------

py_binary(
    name = "contrib/cavp_generate",
    srcs = [":contrib/cavp_generate.py"],
)
