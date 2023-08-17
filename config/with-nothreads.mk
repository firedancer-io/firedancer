include config/with-hosted.mk

CPPFLAGS+=-DFD_HAS_ATOMIC=1
LDFLAGS+=-pthread # Just for Solana right now

FD_HAS_ATOMIC:=1
