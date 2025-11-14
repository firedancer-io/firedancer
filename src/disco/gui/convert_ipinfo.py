#!/usr/bin/env python3
import struct
import ipaddress
import csv
import argparse
import zstandard as zstd

def main():
    parser = argparse.ArgumentParser(description='Convert IPInfo CSV to binary format')
    parser.add_argument('input', help='Input CSV file path')
    parser.add_argument('output', help='Output binary file path')
    args = parser.parse_args()

    country_codes = set()
    with open(args.input, 'r') as r:
        reader = csv.DictReader(r)
        for row in reader:
            try:
                ipaddress.IPv4Network(row['network'])
            except ipaddress.AddressValueError:
                continue
            assert len(row['country_code']) == 2
            country_codes.add(row['country_code'])

    assert len(country_codes) < 256, f"Too many country codes ({len(country_codes)}) to fit in a byte (max 255)"

    country_to_index = {cc: idx for idx, cc in enumerate(sorted(country_codes))}

    with open(args.input, 'r') as r:
        reader = csv.DictReader(r)
        with open(args.output, 'wb') as f:
            cctx = zstd.ZstdCompressor(level=22)
            with cctx.stream_writer(f) as w:
                w.write(struct.pack('<Q', len(country_codes)))
                for cc in sorted(country_codes):
                    w.write(cc.encode('ascii'))

                records = 0
                for row in reader:
                    try:
                        network = ipaddress.IPv4Network(row['network'])
                    except ipaddress.AddressValueError:
                        continue

                    country_idx = country_to_index[row['country_code']]

                    w.write(struct.pack('>I', int(network.network_address)))
                    w.write(struct.pack('<B', network.prefixlen))
                    w.write(struct.pack('<B', country_idx))
                    records += 1

    print(f"Converted {records} records with {len(country_codes)} country codes to {args.output}")

if __name__ == "__main__":
    main()
