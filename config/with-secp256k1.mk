
ifneq ($(SECP256K1),)

ifneq (,$(wildcard $(SECP256K1)/lib/libsecp256k1.a))
CFLAGS += -I$(SECP256K1)/include -DFD_HAS_SECP256K1=1
LDFLAGS += $(SECP256K1)/lib/libsecp256k1.a
FD_HAS_SECP256K1:=1
endif

else

CFLAGS += -DFD_HAS_SECP256K1=1
LDFLAGS += $(shell pkg-config --libs secp256k1)
FD_HAS_SECP256K1:=1

endif

