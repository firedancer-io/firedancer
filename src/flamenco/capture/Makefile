PYTHON=python3.11
NANOPB=/usr/local/bin/nanopb_generator.py

.PHONY: protobuf
protobuf: fd_solcap.pb.h fd_solcap.pb.c

fd_solcap.pb.h fd_solcap.pb.c: fd_solcap.proto
	$(PYTHON) $(NANOPB) $<
	sed -i 's/<pb.h>/\"..\/nanopb\/pb.h\"/g' fd_solcap.pb.h

.PHONY: clean
clean:
	rm -f fd_solcap.pb.h fd_solcap.pb.c
