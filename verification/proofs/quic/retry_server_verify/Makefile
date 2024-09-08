HARNESS_ENTRY = harness
HARNESS_FILE = fd_quic_retry_server_verify_harness
PROOF_UID = fd_quic_retry_server_verify

INCLUDES += -I$(SRCDIR)

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROOF_SOURCES += $(PROOF_STUB)/fd_aes.c
PROJECT_SOURCES = $(SRCDIR)/waltz/quic/fd_quic_retry.c

UNWINDSET += fd_quic_retry_token_verify.0:16
UNWINDSET += memcmp.0:21

CBMC_FLAG_UNSIGNED_OVERFLOW_CHECK =

include ../../Makefile.common
