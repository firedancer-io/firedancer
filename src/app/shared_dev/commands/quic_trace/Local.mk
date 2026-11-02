ifdef FD_HAS_HOSTED
$(call add-objs,fd_quic_trace_frame,fd_app_dev)
$(call add-objs,fd_quic_trace_main,fd_app_dev)
$(call add-objs,fd_quic_trace_rx_tile,fd_app_dev)
$(call add-objs,fd_quic_trace_log_tile,fd_app_dev)
endif
