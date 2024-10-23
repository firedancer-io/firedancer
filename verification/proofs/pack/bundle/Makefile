HARNESS_ENTRY = harness
HARNESS_FILE = fd_pack_bundle_ordering_proof

CHECKFLAGS = --incremental-smt2-solver "z3 -smt2 -in"
PROOF_UID = fd_pack_bundle_ordering

DEFINES +=
INCLUDES += -I$(SRCDIR)

REMOVE_FUNCTION_BODY +=

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROOF_SOURCES += $(PROOF_STUB)/fd_log.c
PROJECT_SOURCES = 

UNWINDSET = harness.0:3

include ../../Makefile.common
