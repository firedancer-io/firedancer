$(call add-hdrs,fd_prometheus.h fd_metrics.h generated/fd_event.h generated/fd_event_metrics.h generated/fd_metric_event_snap.h)
$(call add-objs,fd_prometheus fd_metrics generated/fd_event generated/fd_metric_event_snap,fd_disco)
