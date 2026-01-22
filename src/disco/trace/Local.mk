# Thread-local tracing config
$(call add-hdrs,fd_trace_target.h)
$(call add-objs,fd_trace_target,fd_disco)

# Trace to .fxt exporter
$(call add-hdrs,fd_trace_export.h)
$(call add-objs,fd_trace_export,fd_disco)
$(call add-objs,generated/fd_trace_strings,fd_disco)
