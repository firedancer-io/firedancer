"Wraps C/C++ build toolchain rules"

load(
    ":fd_library.bzl",
    _fd_cc_library = "fd_cc_library",
)
load(
    ":fd_binary.bzl",
    _fd_cc_binary = "fd_cc_binary",
)
load(
    ":fd_test.bzl",
    _fd_cc_test = "fd_cc_test",
)

def fd_package():
    native.package(default_visibility = ["//visibility:public"])

# Exports :fd_library.bzl
fd_cc_library = _fd_cc_library

# Exports :fd_binary.bzl
fd_cc_binary = _fd_cc_binary

# Exports :fd_test.bzl
fd_cc_test = _fd_cc_test
