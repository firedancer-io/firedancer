$(call add-hdrs,fd_circbuf.h generated/fd_event.h)
$(call add-objs,fd_circbuf generated/fd_event,fd_disco)

$(call make-unit-test,test_circbuf,test_circbuf,fd_disco fd_flamenco fd_tango fd_util)
$(call run-unit-test,test_circbuf)
