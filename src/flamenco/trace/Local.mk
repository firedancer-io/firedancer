$(call gen-protobuf,fd_trace)
$(call add-objs,fd_trace.pb fd_txntrace,fd_flamenco)
$(call fuzz-test,fuzz_txntrace,fuzz_txntrace,fd_flamenco fd_funk fd_ballet fd_util)
$(call make-bin,fd_txntrace,fd_txntrace_main,fd_flamenco fd_funk fd_ballet fd_util)
