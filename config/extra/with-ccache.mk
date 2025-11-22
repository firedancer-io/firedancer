# WARNING: This is intended for development. Do not use in prod.
# ccache speeds up building on some systems by skipping compiler
# invocations if the preprocessed input did not change.
#
# Be aware that:
# - Firedancer heavily uses .incbin (FD_IMPORT macros).  ccache is not
#   compatible with this behavior.  You will have to `make clean` if you
#   change an .incbin file.

CCACHE?=ccache
CC:=$(CCACHE) $(CC)
CXX:=$(CCACHE) $(CXX)
CCACHE_SLOPPINESS:=incbin
export CCACHE_SLOPPINESS
