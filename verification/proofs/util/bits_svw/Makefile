HARNESS_ENTRY = harness
HARNESS_FILE = fd_bits_svw_harness

PROOF_UID = fd_bits_svw

DEFINES +=
INCLUDES += -I$(SRCDIR)

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c

UNWINDSET += memcmp.0:10

CBMC_FLAG_CONVERSION_CHECK =
CBMC_FLAG_UNSIGNED_OVERFLOW_CHECK =

include ../../Makefile.common
