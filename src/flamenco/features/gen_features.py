
# solana feature status -u mainnet-beta --output json --display-all > mainnet-beta.jsno
# solana feature status -u devnet --output json --display-all > devnet.json
# solana feature status -u testnet --output json --display-all > testnet.json

import json
import sys

with open('feature_map.json', 'r') as json_file:
    feature_map = json.load(json_file)

with open('../features/devnet.json', 'r') as json_file:
    devnet = json.load(json_file)

with open('../features/testnet.json', 'r') as json_file:
    testnet = json.load(json_file)

with open('../features/mainnet-beta.json', 'r') as json_file:
    mainnet = json.load(json_file)

with open('../features/v13.json', 'r') as json_file:
    v13 = json.load(json_file)

with open('../features/v14.json', 'r') as json_file:
    v14 = json.load(json_file)

with open('../features/v16.json', 'r') as json_file:
    v16 = json.load(json_file)

with open('../features/v17.json', 'r') as json_file:
    v17 = json.load(json_file)

header = open(sys.argv[1], "w")
body = open(sys.argv[2], "w")

print("#ifndef HEADER_fd_features_h", file=header);
print("#define HEADER_fd_features_h", file=header);

print("#include \"./fd_acc_mgr.h\"", file=header);

print("#define FD_FEATURE_ACTIVE(_g, _y)  ((_g->features. _y != 0) && (_g->bank.slot >= _g->features. _y))", file=header)

print ("typedef struct fd_features {", file=header)

rmap = {}
fm = feature_map
for x in fm:
    print ("ulong {};".format(x["name"]), file=header)
    rmap[x["pubkey"]] = x["name"]
print ("} fd_features_t;", file=header)

print ("void fd_enable_testnet(struct fd_features *);", file=header)
print ("void fd_enable_devnet(struct fd_features *);", file=header)
print ("void fd_enable_mainnet(struct fd_features *);", file=header)
print ("void fd_enable_v13(struct fd_features *);", file=header)
print ("void fd_enable_v14(struct fd_features *);", file=header)
print ("void fd_enable_v16(struct fd_features *);", file=header)
print ("void fd_enable_v17(struct fd_features *);", file=header)
print ("void fd_enable_everything(struct fd_features *);", file=header)
print ("void fd_update_features(fd_global_ctx_t * global);", file=header)
print ("void fd_update_feature(fd_global_ctx_t * global, ulong *, const char *key);", file=header)

print ("#include \"fd_features.h\"", file=body);
print ("#include \"fd_runtime.h\"", file=body);
print ("void fd_enable_testnet(struct fd_features *f) {", file=body)
print ("fd_memset(f, 0, sizeof(*f));", file=body)
for x in testnet["features"]:
    if x["status"] == "active":
        print("f->{} = {}; // {}".format(rmap[x["id"]], x["sinceSlot"], x["description"]), file=body)
print ("}", file=body)

print ("void fd_enable_devnet(struct fd_features *f) {", file=body)
print ("fd_memset(f, 0, sizeof(*f));", file=body)
for x in devnet["features"]:
    if x["status"] == "active":
        print("f->{} = {}; // {}".format(rmap[x["id"]], x["sinceSlot"], x["description"]), file=body)
print ("}", file=body)

print ("void fd_enable_mainnet(struct fd_features *f) {", file=body)
print ("fd_memset(f, 0, sizeof(*f));", file=body)
for x in mainnet["features"]:
    if x["status"] == "active":
        print("f->{} = {}; // {}".format(rmap[x["id"]], x["sinceSlot"], x["description"]), file=body)
print ("}", file=body)

print ("void fd_enable_v13(struct fd_features *f) {", file=body)
print ("fd_memset(f, 0, sizeof(*f));", file=body)
for x in v13["features"]:
    if x["status"] == "active":
        if x["id"] in rmap:
            print("f->{} = {}; // {}".format(rmap[x["id"]], x["sinceSlot"], x["description"]), file=body)
print ("}", file=body)

print ("void fd_enable_v14(struct fd_features *f) {", file=body)
print ("fd_memset(f, 0, sizeof(*f));", file=body)
for x in v14["features"]:
    if x["status"] == "active":
        if x["id"] in rmap:
            print("f->{} = {}; // {}".format(rmap[x["id"]], x["sinceSlot"], x["description"]), file=body)
print ("}", file=body)

print ("void fd_enable_v16(struct fd_features *f) {", file=body)
print ("fd_memset(f, 0, sizeof(*f));", file=body)
for x in v16["features"]:
    if x["status"] == "active":
        if x["id"] in rmap:
            print("f->{} = {}; // {}".format(rmap[x["id"]], x["sinceSlot"], x["description"]), file=body)
print ("}", file=body)

print ("void fd_enable_v17(struct fd_features *f) {", file=body)
print ("fd_memset(f, 0, sizeof(*f));", file=body)
for x in v17["features"]:
    if x["status"] == "active":
        if x["id"] in rmap:
            print("f->{} = {}; // {}".format(rmap[x["id"]], x["sinceSlot"], x["description"]), file=body)
print ("}", file=body)

print ("void fd_enable_everything(struct fd_features *f) {", file=body)
print ("fd_memset(f, 0, sizeof(*f));", file=body)
for x in mainnet["features"]:
    print("f->{} = 1; // {}".format(rmap[x["id"]], x["description"]), file=body)
print ("}", file=body)

print ("void fd_update_features(fd_global_ctx_t * global) {", file=body)
for x in mainnet["features"]:
    print("fd_update_feature(global, &global->features.{}, \"{}\");".format(rmap[x["id"]], x["id"]), file=body)
print ("}", file=body)

print("#endif", file=header);
