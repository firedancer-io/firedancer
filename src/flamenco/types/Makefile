PYTHON=python3.11
NANOPB=/usr/local/bin/nanopb_generator.py

.PHONY: all
all:
	@make -C ../../..

.PHONY: clean
clean:
	@make -C ../../.. clean

.PHONY: stubs
stubs: fd_types.json
	python3 gen_stubs.py fd_types.h fd_types.c

# sudo dnf install -y protobuf-compiler python3.11 python3.11-pip
# git clone https://github.com/nanopb/nanopb
# cd nanopb
# mkdir build
# cd build
# cmake .. -Dnanopb_PYTHON_INSTDIR_OVERRIDE=/usr/lib64/python3.11/site-packages
# make -j
# sudo make install

.PHONY: protobuf
protobuf:
	$(PYTHON) $(NANOPB) fd_solana_block.proto
