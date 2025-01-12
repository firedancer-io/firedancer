ifdef FD_HAS_SSE
$(call add-objs,fd_quic_trace_frame,fd_fddev)
$(call add-objs,fd_quic_trace_main,fd_fddev)
$(call add-objs,fd_quic_trace_rx_tile,fd_fddev)
$(call add-objs,fd_quic_trace_log_tile,fd_fddev)
endif
