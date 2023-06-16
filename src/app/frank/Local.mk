ifdef FD_HAS_OPENSSL
# quic is not included in this demo
$(call make-bin,fd_frank_run.bin,fd_frank_main fd_frank_replay fd_frank_parser fd_frank_verify fd_frank_dedup fd_frank_pack,fd_wiredancer fd_wiredancer_test fd_disco fd_ballet fd_tango fd_quic fd_util)
$(call make-bin,fd_frank_mon.bin,fd_frank_mon.bin,fd_disco fd_ballet fd_tango fd_util)
$(call make-bin,wd_frank_mon.bin,wd_frank_mon.bin wd_frank_f1_mon,fd_wiredancer fd_tango fd_util)
$(call add-scripts,fd_frank_init fd_frank_init_demo fd_frank_run fd_frank_mon fd_frank_fini wd_frank_mon)
endif

