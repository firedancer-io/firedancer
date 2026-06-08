# Default Clang executables
ifeq ($(CROSS),)
CC=zig cc
CXX=zig c++
LD=zig c++
endif
