ifdef FD_HAS_HOSTED
ifdef FD_HAS_INT128
$(call make-bin,fd_backtest_ctl,fd_backtest_ctl,fd_flamenco fd_funk fd_ballet fd_util)
endif
endif
