HARNESS_ENTRY = harness
HARNESS_FILE = fd_tls_server_hs_harness
PROOF_UID = fd_tls_server_hs

INCLUDES += -I$(SRCDIR)

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROOF_SOURCES += $(PROOF_STUB)/fd_log.c
PROOF_SOURCES += $(PROOF_STUB)/fd_ed25519.c
PROOF_SOURCES += $(PROOF_STUB)/fd_aes.c
PROOF_SOURCES += $(PROOF_STUB)/fd_sha.c
PROOF_SOURCES += $(PROOF_STUB)/fd_tls_proto.c
PROOF_SOURCES += $(PROOF_STUB)/fd_tls_sign.c
PROJECT_SOURCES = $(SRCDIR)/waltz/tls/fd_tls.c

CBMC_OBJECT_BITS = 16
UNWINDSET += harness.0:8
UNWINDSET += fd_tls_server_hs_wait_finished.0:128
UNWINDSET += fd_tls_has_alpn.0:32

CBMC_FLAG_UNSIGNED_OVERFLOW_CHECK =

include ../../Makefile.common
