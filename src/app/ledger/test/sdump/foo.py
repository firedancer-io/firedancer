import json
import sys
import base58
  
# Opening JSON file
f = open('q.json')
  
# returns JSON object as 
# a dictionary
data = json.load(f)

def vecToString(s):
    t2 = bytearray()
    for x in s:
        t2.append(x)
    return base58.b58encode(t2).decode("utf-8")
    
for block in data:
    for trans in block["transactions"]:
        sigs = trans["transaction"]["signatures"]
        if len(sigs) > 0:
            for idx in range(1,len(sigs)):
                sigs[idx] = vecToString(sigs[idx])
        msgs = trans["transaction"]["message"];
        for m in msgs:
            accounts = m["accountKeys"]

            if len(accounts) > 0:
                for idx in range(1,len(accounts)):
                    accounts[idx] = vecToString(accounts[idx])

            m["recentBlockhash"] = vecToString(m["recentBlockhash"]);

print(json.dumps(data, indent=2))
#t = data[1]["transactions"][0]["transaction"]["signatures"][1]
#t2 = bytearray()
#for x in t:
#    t2.append(x)
#print(base58.b58encode(t2))
#print(len(t2))
#print(len(base58.b58decode("EBx7ukSFjerkzdrZqe4oSnehaubUiQpQ6NEhzR5SpuXoQsGxpaWg2r16MQ2XrVFQcaPfCGUVvFRNQsr23PD7Mu7")))
