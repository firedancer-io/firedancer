ifneq (,$(wildcard $(OPT)/lib/libsecp256k1.a))
FD_HAS_SECP256K1:=1
CFLAGS+=-DFD_HAS_SECP256K1=1
SECP256K1_LIBS:=$(OPT)/lib/libsecp256k1.a
LDFLAGS+=$(SECP256K1_LIBS)
else
$(warning "secp256k1 not installed, skipping")
endif
