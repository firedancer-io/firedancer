HARNESS_ENTRY = harness
HARNESS_FILE = fd_txn_ambiguity_gossip_proof

PROOF_UID = fd_txn_ambiguity_gossip

DEFINES +=
INCLUDES += -I$(SRCDIR)

REMOVE_FUNCTION_BODY +=

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROJECT_SOURCES = $(SRCDIR)/ballet/txn/fd_txn_parse.c

include ../../Makefile.common
