BUILDDIR:=rh8/minimal_clang

include config/base.mk
include config/with-clang.mk
include config/with-debug.mk
include config/with-brutality.mk
include config/with-optimization.mk
include config/with-hosted.mk

