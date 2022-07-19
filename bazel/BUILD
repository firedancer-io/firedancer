load("@bazel_skylib//rules:common_settings.bzl", "bool_flag")
load("//bazel:fd_build_system.bzl", "fd_package")

fd_package()

# --------------------------------
# Platforms
# --------------------------------

platform(
    name = "rh8_x86_64",
    constraint_values = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_64",
        # TODO distro
    ],
)

platform(
    name = "macos_x86_64",
    constraint_values = [
        "@platforms//os:macos",
        ":nothreads",
    ],
)

# --------------------------------
# Config settings
# --------------------------------

config_setting(
    name = "opt_build",
    values = {"compilation_mode": "opt"},
)

config_setting(
    name = "dbg_build",
    values = {"compilation_mode": "dbg"},
)

config_setting(
    name = "brutality",
    define_values = {
        "brutal": "1",
    },
)

config_setting(
    name = "machine_icelake",
    define_values = {
        "machine": "icelake",
    },
)

config_setting(
    name = "nothreads",
    flag_values = {
        "threads": "false",
    },
)

# --------------------------------
# Flags
# --------------------------------

bool_flag(
    name = "threads",
    build_setting_default = True,
)
