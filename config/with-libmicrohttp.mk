ifneq ($(LIBMICROHTTP),)

ifneq (,$(wildcard $(LIBMICROHTTP)/liblibmicrohttp.a))
CFLAGS += -I$(LIBMICROHTTP)/include -DFD_HAS_LIBMICROHTTP=1
LDFLAGS += -lstdc++ $(LIBMICROHTTP)/liblibmicrohttp.a
FD_HAS_LIBMICROHTTP:=1
endif

else

CFLAGS += -DFD_HAS_LIBMICROHTTP=1
CFLAGS += $(shell pkg-config --cflags-only-I libmicrohttpd)
LDFLAGS += $(shell pkg-config --libs libmicrohttpd)
FD_HAS_LIBMICROHTTP:=1

endif
