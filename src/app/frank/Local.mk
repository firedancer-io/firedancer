ifdef FD_HAS_DOUBLE
$(call make-bin,fd_frank_run.bin,fd_frank_main fd_frank_verify fd_frank_dedup fd_frank_quic fd_frank_pack fd_frank,fd_disco fd_ballet fd_tango fd_util fd_quic)
$(call make-bin,fd_frank_mon.bin,fd_frank_mon.bin fd_frank,fd_disco fd_ballet fd_tango fd_util)
$(call add-scripts,fd_frank_init fd_frank_run fd_frank_mon fd_frank_fini)
endif
