HARNESS_ENTRY = harness
HARNESS_FILE = fd_txn_minsz_harness

PROOF_UID = fd_txn_minsz

DEFINES +=
INCLUDES += -I$(SRCDIR)

REMOVE_FUNCTION_BODY +=

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROOF_SOURCES += $(PROOF_STUB)/fd_log.c
PROJECT_SOURCES = $(SRCDIR)/ballet/txn/fd_txn_parse.c

include ../../Makefile.common
