PYTHON?=python3

.PHONY: metrics metrics-assign
metrics:
	$(PYTHON) ./fmt_metrics.py
	$(PYTHON) ./lint_metrics.py
	$(PYTHON) ./gen_metrics.py

# Before landing: replace provisional event ids and field numbers in the
# metrics event schemas with the next free ones
metrics-assign: metrics
	$(PYTHON) ./gen_metrics.py --assign
