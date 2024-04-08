HARNESS_ENTRY = harness
HARNESS_FILE = fd_quic_decrypt_harness
PROOF_UID = fd_quic_decrypt

INCLUDES += -I$(SRCDIR)

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROOF_SOURCES += $(PROOF_STUB)/fd_log.c
PROOF_SOURCES += $(PROOF_STUB)/fd_aes.c
PROJECT_SOURCES = $(SRCDIR)/tango/quic/crypto/fd_quic_crypto_suites.c

UNWINDSET += fd_quic_crypto_decrypt_hdr.1:8
UNWINDSET += fd_quic_crypto_decrypt.0:5

include ../Makefile.quic.common
include ../../Makefile.common
