HARNESS_ENTRY = harness
HARNESS_FILE = fd_quic_decode_initial_harness
PROOF_UID = fd_quic_decode_initial

INCLUDES += -I$(SRCDIR)

UNWINDSET += fd_quic_decode_initial.0:64
UNWINDSET += fd_quic_decode_initial.1:64
UNWINDSET += fd_quic_decode_initial.2:256

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROOF_SOURCES += $(PROOF_STUB)/fd_log.c
PROJECT_SOURCES = $(SRCDIR)/waltz/quic/fd_quic_proto.c

UNWINDSET += fd_quic_parse_bits:8

include ../../Makefile.common
