HARNESS_ENTRY = harness
HARNESS_FILE = fd_quic_process_packet_harness
PROOF_UID = fd_quic_process_packet

INCLUDES += -I$(SRCDIR)

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROOF_SOURCES += $(PROOF_STUB)/fd_log.c
PROJECT_SOURCES = $(SRCDIR)/waltz/quic/fd_quic.c
REMOVE_FUNCTION_BODY += fd_quic_conn_map_query
REMOVE_FUNCTION_BODY += fd_quic_process_quic_packet_v1

UNWINDSET += fd_quic_process_packet.0:16

CBMC_FLAG_UNSIGNED_OVERFLOW_CHECK =

include ../../Makefile.common
