ifdef FD_HAS_HOSTED
$(call add-hdrs,fd_prometheus.h fd_metrics.h)
$(call add-objs,fd_prometheus fd_metrics,fd_disco)
ifdef FD_HAS_ALLOCA
$(call add-objs,fd_metric_tile,fd_disco)
endif
endif

$(wildcard src/disco/metrics/generated/fd_metrics_*.h src/disco/metrics/generated/fd_metrics_*.c) &: src/disco/metrics/metrics.xml
	$(MAKE) -C src/disco/metrics
