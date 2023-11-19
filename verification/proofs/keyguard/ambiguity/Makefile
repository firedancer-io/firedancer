HARNESS_ENTRY = harness
HARNESS_FILE = fd_keyguard_ambiguity_proof
PROOF_UID = fd_keyguard_ambiguity

INCLUDES += -I$(SRCDIR)

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROJECT_SOURCES = $(SRCDIR)/disco/keyguard/fd_keyguard_match.c

UNWINDSET += memcmp.0:1024

include ../../Makefile.common
