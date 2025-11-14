include config/extra/with-handholding.mk
include config/extra/with-debug.mk
CPPFLAGS+=-DFD_SPAD_TRACK_USAGE=1
CFLAGS+=-DFD_SPAD_TRACK_USAGE=1

CPPFLAGS+=-DFD_OFFLINE_REPLAY=1
CFLAGS+=-DFD_OFFLINE_REPLAY=1
