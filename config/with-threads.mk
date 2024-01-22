include config/with-hosted.mk

CPPFLAGS+=-pthread -DFD_HAS_THREADS=1 -DFD_HAS_ATOMIC=1
LDFLAGS+=-pthread

FD_HAS_THREADS:=1
FD_HAS_ATOMIC:=1
