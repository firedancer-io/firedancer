import base58

def main():
    f = open('hashes.txt', 'r')
    for line in f:
        slot_str, hash = line.strip().split(',')
        slot_idx = int(slot_str) - 368528501
        hash_bytes = base58.b58decode(hash)
        # print C style array of bytes
        print(f"[ {slot_idx} ] = {{ {', '.join(f'0x{b:02x}' for b in hash_bytes)} }},")

if __name__ == "__main__":
    main()
