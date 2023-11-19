HARNESS_ENTRY = harness
HARNESS_FILE = fd_quic_handle_v1_one_rtt_harness
PROOF_UID = fd_quic_handle_v1_one_rtt

INCLUDES += -I$(SRCDIR)

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROOF_SOURCES += $(PROOF_STUB)/fd_log.c
PROOF_SOURCES += $(PROOF_STUB)/fd_quic_crypto.c
PROJECT_SOURCES += $(SRCDIR)/tango/quic/fd_quic.c
PROJECT_SOURCES += $(SRCDIR)/tango/quic/fd_quic_proto.c

REMOVE_FUNCTION_BODY += fd_quic_handle_v1_frame
REMOVE_FUNCTION_BODY += fd_quic_parse_bits
REMOVE_FUNCTION_BODY += fd_quic_conn_close
REMOVE_FUNCTION_BODY += fd_quic_conn_error
REMOVE_FUNCTION_BODY += fd_quic_ack_enc_level
REMOVE_FUNCTION_BODY += fd_quic_aio_cb_receive

UNWINDSET += fd_quic_decode_one_rtt.1:32
UNWINDSET += fd_quic_handle_v1_one_rtt.5:8

CBMC_FLAG_UNSIGNED_OVERFLOW_CHECK =

include ../../Makefile.common
