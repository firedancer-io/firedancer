
import json
import sys

with open('feature_map.json', 'r') as json_file:
    feature_map = json.load(json_file)

with open('devnet.json', 'r') as json_file:
    devnet = json.load(json_file)

with open('testnet.json', 'r') as json_file:
    testnet = json.load(json_file)

with open('mainnet-beta.json', 'r') as json_file:
    mainnet = json.load(json_file)

header = open(sys.argv[1], "w")
body = open(sys.argv[2], "w")

print("#ifndef HEADER_fd_features_h", file=header);
print("#define HEADER_fd_features_h", file=header);

print("#include \"./fd_acc_mgr.h\"", file=header);


print ("typedef struct fd_features {", file=header)

rmap = {}
fm = feature_map["feature_map"]
for x in fm:
    print ("uchar {};".format(x), file=header)
    rmap[fm[x]] = x
print ("} fd_features_t;", file=header)

print ("void enable_testnet(struct fd_features *);", file=header)
print ("void enable_devnet(struct fd_features *);", file=header)
print ("void enable_mainnet(struct fd_features *);", file=header)

print ("#include \"fd_features.h\"", file=body);
print ("void enable_testnet(struct fd_features *f) {", file=body)
print ("fd_memset(f, 0, sizeof(*f));", file=body)
for x in testnet["features"]:
    if x["status"] == "active":
        print("f->{} = 1;".format(rmap[x["id"]]), file=body)
print ("}", file=body)

print ("void enable_devnet(struct fd_features *f) {", file=body)
print ("fd_memset(f, 0, sizeof(*f));", file=body)
for x in devnet["features"]:
    if x["status"] == "active":
        print("f->{} = 1;".format(rmap[x["id"]]), file=body)
print ("}", file=body)

print ("void enable_mainnet(struct fd_features *f) {", file=body)
print ("fd_memset(f, 0, sizeof(*f));", file=body)
for x in mainnet["features"]:
    if x["status"] == "active":
        print("f->{} = 1;".format(rmap[x["id"]]), file=body)
print ("}", file=body)

print("#endif", file=header);
