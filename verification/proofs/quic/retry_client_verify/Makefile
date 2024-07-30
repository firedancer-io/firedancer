HARNESS_ENTRY = harness
HARNESS_FILE = fd_quic_retry_client_verify_harness
PROOF_UID = fd_quic_retry_client_verify

INCLUDES += -I$(SRCDIR)

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROOF_SOURCES += $(PROOF_STUB)/fd_aes.c
PROOF_SOURCES += $(PROOF_STUB)/fd_log.c
PROJECT_SOURCES += $(SRCDIR)/waltz/quic/fd_quic_retry.c
PROJECT_SOURCES += $(SRCDIR)/waltz/quic/fd_quic_proto.c
PROJECT_SOURCES += $(SRCDIR)/waltz/quic/templ/fd_quic_parse_util.c

UNWINDSET += fd_quic_decode_retry_hdr.0:21
UNWINDSET += fd_quic_decode_retry_hdr.1:21
UNWINDSET += fd_quic_parse_bits:8

REMOVE_FUNCTION_BODY += fd_quic_retry_pseudo

include ../../Makefile.common
