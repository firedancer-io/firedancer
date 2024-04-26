# python3.8 -m pip install fd58 --user
# PYTHON=python3.8 make

PYTHON?=python3
BLACK?=$(PYTHON) -m black

.PHONY: generate
generate: fd_features_generated.h fd_features_generated.c

fd_features_generated.h fd_features_generated.c: gen_features.py feature_map.json
	$(PYTHON) gen_features.py

.PHONY: format
format:
	$(BLACK) gen_features.py
