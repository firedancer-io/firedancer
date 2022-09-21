load("@bazel_skylib//lib:selects.bzl", "selects")

# --------------------------------
# Config Settings
# --------------------------------

config_setting(
    name = "brutality_1",
    flag_values = {"//:brutality": "1"},
)

config_setting(
    name = "brutality_2",
    flag_values = {"//:brutality": "2"},
)

config_setting(
    name = "opt_build",
    values = {"compilation_mode": "opt"},
)

config_setting(
    name = "dbg_build_mode",
    values = {"compilation_mode": "dbg"},
)

config_setting(
    name = "dbg_build_flag",
    flag_values = {"//:dbg": "True"},
)

selects.config_setting_group(
    name = "dbg_build",
    match_any = [
        ":dbg_build_mode",
        ":dbg_build_flag",
    ],
)

config_setting(
    name = "has_int128",
    define_values = {"FD_HAS_INT128": "1"},
)

config_setting(
    name = "has_hosted",
    constraint_values = [
        "@platforms//os:linux",
    ],
    flag_values = {
        "//:hosted": "True",
    },
)

config_setting(
    name = "has_threads",
    constraint_values = [
        "@platforms//os:linux",
    ],
    flag_values = {
        "//:threads": "True",
    },
)
