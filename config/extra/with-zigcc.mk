# Experimental cross-compiling via `zig cc`.
#
# Not recommended for production:
# As of Zig 0.15, 'zig cc' includes undocumented breaking behavior
# changes, like passing `-NDEBUG`, and system header precedence bugs.
include config/extra/with-clang.mk
