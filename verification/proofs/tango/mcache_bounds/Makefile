HARNESS_ENTRY = harness
HARNESS_FILE = fd_mcache_bounds_harness
PROOF_UID = fd_mcache_bounds

INCLUDES += -I$(SRCDIR)

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROOF_SOURCES += $(PROOF_STUB)/fd_log.c
PROJECT_SOURCES = $(SRCDIR)/tango/mcache/fd_mcache.c

CBMC_FLAG_UNSIGNED_OVERFLOW_CHECK =

include ../../Makefile.common
