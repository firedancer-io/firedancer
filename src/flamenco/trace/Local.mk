ifdef FD_HAS_INT128
$(call gen-protobuf,fd_trace)
$(call add-objs,fd_trace.pb fd_txntrace,fd_flamenco)
ifdef FD_HAS_HOSTED
$(call fuzz-test,fuzz_txntrace,fuzz_txntrace,fd_flamenco fd_funk fd_ballet fd_util)
$(call make-bin,fd_txntrace,fd_txntrace_main,fd_flamenco fd_funk fd_ballet fd_util)
endif
endif
