PYTHON?=python3
UNCRUSTIFY?=uncrustify
BLACK?=$(PYTHON) -m black

features.h features.c: gen_features.py $(wildcard *.json)
	$(PYTHON) gen_features.py fd_features.h fd_features.c
	$(UNCRUSTIFY) -c ../../../contrib/lint.cfg --no-backup --replace fd_features.h
	$(UNCRUSTIFY) -c ../../../contrib/lint.cfg --no-backup --replace fd_features.c

.PHONY: format
format:
	$(BLACK) gen_features.py
