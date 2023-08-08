PYTHON?=python3
UNCRUSTIFY?=uncrustify
BLACK?=$(PYTHON) -m black

#solana feature status -u mainnet-beta --output json --display-all > mainnet-beta.json
#solana feature status -u testnet --output json --display-all > testnet.json
#solana feature status -u devnet --output json --display-all > devnet.json

features.h features.c: gen_features.py $(wildcard *.json)
	$(PYTHON) gen_features.py fd_features.h fd_features.c
	$(UNCRUSTIFY) -c ../../../lint.cfg --no-backup --replace fd_features.h
	$(UNCRUSTIFY) -c ../../../lint.cfg --no-backup --replace fd_features.c

.PHONY: format
format:
	$(BLACK) gen_features.py
