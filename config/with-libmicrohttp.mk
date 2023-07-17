ifneq ($(LIBMICROHTTP),)

ifneq (,$(wildcard $(LIBMICROHTTP)/liblibmicrohttp.a))
CFLAGS += -I$(LIBMICROHTTP)/include -DFD_HAS_LIBMICROHTTP=1
LDFLAGS += -lstdc++ $(LIBMICROHTTP)/liblibmicrohttp.a
FD_HAS_LIBMICROHTTP:=1
endif

else

CFLAGS += -DFD_HAS_LIBMICROHTTP=1
LDFLAGS += -Wl,--push-state,-Bstatic -lmicrohttpd -Wl,--pop-state
FD_HAS_LIBMICROHTTP:=1

endif
