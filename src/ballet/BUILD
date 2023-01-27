load("//bazel:fd_build_system.bzl", "fd_cc_library")

fd_cc_library(
    name = "base_lib",
    hdrs = [
        "fd_ballet.h",
        "fd_ballet_base.h",
    ],
    linkstatic = True,
    visibility = [":__subpackages__"],
    deps = [
        "//src/util",
    ],
)

fd_cc_library(
    name = "ballet",
    linkstatic = True,
    visibility = ["//visibility:public"],
    deps = [
        ":base_lib",
        "//src/ballet/bmtree",
        "//src/ballet/ed25519",
        "//src/ballet/pack",
        "//src/ballet/poh",
        "//src/ballet/sha256",
        "//src/ballet/sha512",
        "//src/ballet/shred",
        "//src/ballet/txn",
        "//src/ballet/base58",
    ],
)
