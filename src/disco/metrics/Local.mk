$(call add-hdrs,fd_prometheus.h fd_metrics.h)
$(call add-objs,fd_prometheus fd_metrics ,fd_disco)
$(call add-objs,fd_metric_tile,fd_disco)
