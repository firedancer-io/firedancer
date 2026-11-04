ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_prometheus.h fd_metrics.h fd_metrics_sample.h)
$(call add-objs,fd_prometheus fd_metrics fd_metrics_sample,fd_disco)
$(call add-objs,fd_metric_tile,fd_disco)
endif
