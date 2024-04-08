HARNESS_ENTRY = harness
HARNESS_FILE = fd_quic_parse_transport_params_harness
PROOF_UID = fd_quic_parse_transport_params

INCLUDES += -I$(SRCDIR)

PROOF_SOURCES += $(PROOFDIR)/$(HARNESS_FILE).c
PROOF_SOURCES += $(PROOF_STUB)/fd_log.c
PROJECT_SOURCES = $(SRCDIR)/tango/quic/templ/fd_quic_transport_params.c

CBMC_FLAG_UNSIGNED_OVERFLOW_CHECK =

include ../../Makefile.common
