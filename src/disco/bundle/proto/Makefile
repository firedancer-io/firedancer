NANOPB_GEN?=nanopb_generator.py

PROTOS:=
PROTOS+=auth
PROTOS+=block_engine
PROTOS+=bundle
PROTOS+=packet
PROTOS+=shared
PROTOS+=timestamp

.PHONY: generate
generate: $(addsuffix .pb.h,$(PROTOS)) $(addsuffix .pb.c,$(PROTOS))

%.pb.h %.pb.c: %.proto %.options
	$(NANOPB_GEN) --protoc-opt=--experimental_allow_proto3_optional --options-file $(patsubst %.proto,%.options,$<) $<
	sed -i 's|#include <pb.h>|#include "../../../ballet/nanopb/pb_firedancer.h"|' $(patsubst %.proto,%.pb.h,$<)

.PHONY: clean
clean:
	rm -f $(addsuffix .pb.h,$(PROTOS)) $(addsuffix .pb.c,$(PROTOS))
