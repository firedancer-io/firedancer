LDFLAGS+=-Wl,--push-state,-static $(shell pkg-config --libs libbpf libelf libzstd zlib) -Wl,--pop-state

FD_HAS_LIBBPF:=1
CPPFLAGS+=-DFD_HAS_LIBBPF=1
