load("@bazel_skylib//rules:common_settings.bzl", "bool_flag", "int_flag")

package(default_visibility = ["//visibility:public"])

# --------------------------------
# Platforms
# --------------------------------

platform(
    name = "rh8_x86_64",
    constraint_values = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
    ],
)

platform(
    name = "rh8_noarch64",
    constraint_values = [
        "@platforms//os:linux",
    ],
)

platform(
    name = "rh8_noarch128",
    constraint_values = [
        "@platforms//os:linux",
        "//src:has_int128",
    ],
)

# --------------------------------
# Flags
# --------------------------------

int_flag(
    name = "brutality",
    build_setting_default = 0,
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
