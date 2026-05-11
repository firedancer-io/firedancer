# contrib/falcon - self-contained Falcon-512 verification harness
#
# Build:
#   make              # builds bench and test_falcon
#   make bench        # builds the benchmark
#   make test         # builds and runs the correctness tests
#   make latex        # runs ./bench --latex
#   make clean
#
# By default we compile with -march=native so AVX-512 is enabled when the
# host CPU has it.  Build with `make NATIVE=0` to force the scalar path
# in falcon_avx512.c (it then delegates to the vendored reference).
#
# Vendored upstream sources, compiled unmodified:
#   vendor/falcon-round3/   - Pornin et al. NIST round 3 reference
#   vendor/xkcp/            - eXtended Keccak Code Package (XKCP)

CC      ?= gcc
NATIVE  ?= 1

CFLAGS_LOCAL  ?= -O3 -Wall -Wextra -Wno-unused-parameter -fno-strict-aliasing -std=gnu11
CFLAGS_VENDOR ?= -O3 -w
ifeq ($(NATIVE),1)
CFLAGS_LOCAL  += -march=native
CFLAGS_VENDOR += -march=native
endif

# Local sources.
SRC_LOCAL = falcon_ref.c falcon_ref_xkcp.c falcon_ref_turbopar.c \
            falcon_x86.c \
            falcon_avx512_barrett.c falcon_avx512.c falcon_avx512_from_ref.c \
            randombytes_stub.c xkcp_shake.c
HDR_LOCAL = falcon.h falcon_twiddle.h falcon_avx512_common.h \
            test_vectors.h xkcp_shake.h

OBJ_LOCAL = $(SRC_LOCAL:.c=.o)

# Pornin NIST round 3 reference, compiled as-is from vendor/.
PORNIN_DIR = vendor/falcon-round3/Reference_Implementation/falcon512/falcon512int
PORNIN_SRC = $(wildcard $(PORNIN_DIR)/*.c)
PORNIN_OBJ = $(PORNIN_SRC:.c=.o)

# XKCP: build the upstream static libraries via XKCP's own Makefile, then
# extract the single-permutation objects we need for the SHAKE bench.
XKCP_DIR    = vendor/xkcp
XKCP_LIB_P  = $(XKCP_DIR)/bin/generic64/libXKCP.a
XKCP_LIB_A  = $(XKCP_DIR)/bin/AVX512/libXKCP.a
XKCP_OBJ_P  = $(XKCP_DIR)/bin/generic64/KeccakP-1600-opt64.o
XKCP_OBJ_A  = $(XKCP_DIR)/bin/AVX512/KeccakP-1600-AVX512.o
XKCP_OBJ_P8 = $(XKCP_DIR)/bin/AVX512/KeccakP-1600-times8-AVX512.o

OBJ_ALL = $(OBJ_LOCAL) $(PORNIN_OBJ) $(XKCP_OBJ_P) $(XKCP_OBJ_A) $(XKCP_OBJ_P8)

.PHONY: all bench test latex clean xkcp

all: bench test_falcon

bench: bench.o $(OBJ_ALL)
	$(CC) $(CFLAGS_LOCAL) -o $@ $^

test_falcon: test_falcon.o $(OBJ_ALL)
	$(CC) $(CFLAGS_LOCAL) -o $@ $^

# Local sources: warnings on.
bench.o test_falcon.o $(OBJ_LOCAL): %.o: %.c $(HDR_LOCAL)
	$(CC) $(CFLAGS_LOCAL) -c -o $@ $<

# Pornin reference sources: warnings off.
$(PORNIN_OBJ): %.o: %.c
	$(CC) $(CFLAGS_VENDOR) -I $(PORNIN_DIR) -c -o $@ $<

# XKCP libraries: built once via XKCP's own Makefile.  We then pull out the
# single-permutation objects (single-stream KeccakP-1600).  XKCP's `make`
# requires xsltproc to expand its target list; this is a one-time cost.
xkcp: $(XKCP_LIB_P) $(XKCP_LIB_A)

$(XKCP_LIB_P):
	$(MAKE) -C $(XKCP_DIR) generic64/libXKCP.a EXTRA_CFLAGS="$(if $(filter 1,$(NATIVE)),-march=native -mtune=native,)"

$(XKCP_LIB_A):
	$(MAKE) -C $(XKCP_DIR) AVX512/libXKCP.a EXTRA_CFLAGS="$(if $(filter 1,$(NATIVE)),-march=native -mtune=native,)"

$(XKCP_OBJ_P): $(XKCP_LIB_P)
	cd $(XKCP_DIR)/bin/generic64 && ar x libXKCP.a KeccakP-1600-opt64.o

$(XKCP_OBJ_A): $(XKCP_LIB_A)
	cd $(XKCP_DIR)/bin/AVX512 && ar x libXKCP.a KeccakP-1600-AVX512.o

$(XKCP_OBJ_P8): $(XKCP_LIB_A)
	cd $(XKCP_DIR)/bin/AVX512 && ar x libXKCP.a KeccakP-1600-times8-AVX512.o

test: test_falcon
	./test_falcon

latex: bench
	./bench --latex

clean:
	rm -f *.o $(PORNIN_OBJ) bench test_falcon
	rm -rf $(XKCP_DIR)/bin
