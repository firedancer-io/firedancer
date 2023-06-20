$(call make-bin,fd_tguard_run.bin,fd_tguard_main fd_tguard_tqos fd_tguard_tmon,fd_disco fd_ballet fd_tango fd_util)
$(call make-bin,fd_tguard_mon.bin,fd_tguard_mon.bin,fd_disco fd_ballet fd_tango fd_util)
$(call add-scripts,fd_tguard_cnc fd_tguard_init fd_tguard_run fd_tguard_mon fd_tguard_fini)

