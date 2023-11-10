HARNESS_ENTRY = harness
HARNESS_FILE = fd_keyguard_match_txn_harness

PROOF_UID = fd_keyguard_match_txn

DEFINES +=
INCLUDES += -I$(SRCDIR)

REMOVE_FUNCTION_BODY +=

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROJECT_SOURCES += $(SRCDIR)/ballet/txn/fd_txn_parse.c
PROJECT_SOURCES += $(SRCDIR)/disco/keyguard/fd_keyguard_match.c

include ../../Makefile.common
