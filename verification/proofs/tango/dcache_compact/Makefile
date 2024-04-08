HARNESS_ENTRY = harness
HARNESS_FILE = fd_dcache_compact_harness
PROOF_UID = fd_dcache_compact

INCLUDES += -I$(SRCDIR)

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROOF_SOURCES += $(PROOF_STUB)/fd_log.c
PROJECT_SOURCES = $(SRCDIR)/tango/dcache/fd_dcache.c

CBMC_FLAG_UNSIGNED_OVERFLOW_CHECK =

include ../../Makefile.common
