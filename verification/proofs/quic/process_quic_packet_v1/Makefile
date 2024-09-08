HARNESS_ENTRY = harness
HARNESS_FILE = fd_quic_rx_pkt_harness
PROOF_UID = fd_quic_process_packet_v1

INCLUDES += -I$(SRCDIR)

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROJECT_SOURCES = $(SRCDIR)/waltz/quic/fd_quic.c
PROJECT_SOURCES += $(SRCDIR)/waltz/quic/fd_quic_proto.c
REMOVE_FUNCTION_BODY += fd_quic_handle_v1_initial
REMOVE_FUNCTION_BODY += fd_quic_handle_v1_handshake
REMOVE_FUNCTION_BODY += fd_quic_handle_v1_retry
REMOVE_FUNCTION_BODY += fd_quic_handle_v1_zero_rtt
REMOVE_FUNCTION_BODY += fd_quic_handle_v1_one_rtt
REMOVE_FUNCTION_BODY += fd_quic_ack_pkt

UNWINDSET += fd_quic_decode_long_hdr.0:21
UNWINDSET += fd_quic_decode_long_hdr.1:21

include ../../Makefile.common
