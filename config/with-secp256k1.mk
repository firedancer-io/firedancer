ifneq ($(SECP256K1),)

ifneq (,$(wildcard $(SECP256K1)/lib/libsecp256k1.a))
CFLAGS += -I$(SECP256K1)/include
LDFLAGS += $(SECP256K1)/lib/libsecp256k1.a
FD_HAS_SECP256K1:=1
endif

else

LDFLAGS += $(shell pkg-config --libs secp256k1)
FD_HAS_SECP256K1:=1

endif

ifneq ($(FD_HAS_SECP256K1),)

CFLAGS += -DFD_HAS_SECP256K1=1

endif
