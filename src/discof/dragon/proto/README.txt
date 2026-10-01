This directory contains the Dragon's Mouth protocol definitions from
yellowstone-grpc, tag "v16.0.0-rc8+solana.4.3.0.rc.0", subdirectory
yellowstone-grpc-proto/proto.  That subdirectory of yellowstone-grpc is
licensed Apache-2.0 (see LICENSING.md in the upstream repository); see
NOTICE in the root of this repo.

geyser.proto and solana_storage.proto are copies of the upstream
geyser.proto and solana-storage.proto with two changes:

  - solana-storage.proto is renamed solana_storage.proto, so that the
    generated C identifiers and file names contain no dash.
  - geyser.proto imports "timestamp.proto" and "solana_storage.proto"
    from this directory instead of "google/protobuf/timestamp.proto"
    and "solana-storage.proto".

timestamp.proto is the subset of google/protobuf/timestamp.proto that
the generated code needs, as in src/disco/bundle/proto.

The .options files bound the fields nanopb would otherwise allocate;
generate.sh regenerates the checked-in *.pb.h and *.pb.c from them.

health.proto is the gRPC health checking protocol of grpc/health/v1,
unchanged from https://github.com/grpc/grpc-proto (Apache-2.0).  Its
service name is the one thing a client controls the length of, so its
.options file makes it a callback.
