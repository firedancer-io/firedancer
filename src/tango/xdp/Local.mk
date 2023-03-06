$(call add-hdrs,fd_xdp_redirect_prog.h)
$(call make-ebpf-bin,fd_xdp_redirect_prog)

ifdef FD_HAS_HOSTED
ifdef FD_HAS_LIBBPF
$(call make-lib,fd_xdp)
$(call add-hdrs,fd_xdp.h fd_xsk.h fd_xsk_aio.h)
$(call add-objs,fd_xsk fd_xsk_aio fd_xdp_redirect_user,fd_xdp)
$(call make-bin,fd_xdp_ctl,fd_xdp_ctl,fd_xdp fd_util,$(EBPF_BINDIR)/fd_xdp_redirect_prog.o)
$(call make-unit-test,test_xdp_ebpf,test_xdp_ebpf,fd_xdp fd_util,$(EBPF_BINDIR)/fd_xdp_redirect_prog.o $(wildcard src/tango/xdp/fixtures/*.bin))
$(call make-unit-test,test_xdp_unit,test_xdp_unit,fd_xdp fd_util)
$(call make-unit-test,test_xdp_echo_aio,test_xdp_echo_aio,fd_tango fd_xdp fd_util)
$(call add-test-scripts,test_xdp_ctl test_xdp_init test_xdp_full test_xdp_fini)
endif
endif

