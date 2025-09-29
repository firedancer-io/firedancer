#!/usr/bin/env python3

import argparse
import struct
import json
import os
from typing import List, Dict, Any
import binascii
from datetime import datetime
from collections import OrderedDict
import base58

def validate_feccap_file(file_path: str) -> str:
    """Validate that the provided file exists and has .feccap extension."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if not file_path.endswith('.feccap'):
        raise ValueError(f"File must have .feccap extension: {file_path}")

    return os.path.abspath(file_path)

def parse_fd_hash(data: bytes, offset: int) -> tuple:
    """Parse a 32-byte fd_hash_t structure."""
    hash_bytes = data[offset:offset + 32]
    hash_hex = binascii.hexlify(hash_bytes).decode('ascii')
    hash_base58 = base58.b58encode(hash_bytes).decode('ascii')
    return hash_hex, hash_base58, offset + 32

def parse_fd_store_key(data: bytes, offset: int) -> tuple:
    """Parse fd_store_key_t structure (32-byte hash + 8-byte ulong part)."""
    mr_hash_hex, mr_hash_b58, new_offset = parse_fd_hash(data, offset)
    part = struct.unpack('<Q', data[new_offset:new_offset + 8])[0]
    return {
        'mr': mr_hash_b58,
        'mr_hex': mr_hash_hex,
        'part': part
    }, new_offset + 8

def parse_feccap_file(file_path: str, data_limit: int = 100) -> Dict[str, Any]:
    """Parse a .feccap binary file with fec_message + fd_store_fec_t structure format."""
    with open(file_path, 'rb') as f:
        data = f.read()

    if len(data) < 16:
        raise ValueError("File too short to contain header")

    # Parse magic header
    magic_header = data[0:8]
    expected_magic = bytes([0x89, 0x46, 0x45, 0x43, 0x0d, 0x0a, 0x1a, 0x0a])

    if magic_header != expected_magic:
        raise ValueError(f"Invalid magic header: {binascii.hexlify(magic_header).decode()}")

    # Parse FEC count
    fec_count = struct.unpack('<Q', data[8:16])[0]

    # Each record now consists of:
    # - fec_message: 168 bytes (8 bytes size + 160 bytes data)
    # - fd_store_fec_t: 64128 bytes
    FEC_MESSAGE_SIZE = 168
    FD_STORE_FEC_SIZE = 64128
    TOTAL_RECORD_SIZE = FEC_MESSAGE_SIZE + FD_STORE_FEC_SIZE

    # Parse FEC records
    fec_records = []
    offset = 16

    for i in range(fec_count):
        if offset + TOTAL_RECORD_SIZE > len(data):
            print(f"Warning: Expected {fec_count} records but only found {i}")
            break

        # Parse fec_message (168 bytes)
        fec_msg_data = data[offset:offset + FEC_MESSAGE_SIZE]
        fec_msg_size = struct.unpack('<Q', fec_msg_data[0:8])[0]
        fec_msg_chunk_data = fec_msg_data[8:168]  # 160 bytes of chunk data

        # Convert fec_message data to space-separated hex
        fec_msg_hex = binascii.hexlify(fec_msg_chunk_data).decode('ascii')
        fec_msg_hex_spaced = ' '.join(fec_msg_hex[i:i+2] for i in range(0, len(fec_msg_hex), 2))

        # Move to fd_store_fec_t structure
        offset += FEC_MESSAGE_SIZE

        # Extract the fd_store_fec_t record (64128 bytes)
        record_data = data[offset:offset + FD_STORE_FEC_SIZE]
        record_offset = 0

        # Parse key (fd_store_key_t)
        key, record_offset = parse_fd_store_key(record_data, record_offset)

        # Parse cmr (chained merkle root - 32 bytes)
        cmr_hash_hex, cmr_hash_b58, record_offset = parse_fd_hash(record_data, record_offset)

        # Parse pointer fields (next, parent, child, sibling - 4 * 8 bytes)
        next_ptr, parent_ptr, child_ptr, sibling_ptr = struct.unpack('<QQQQ', record_data[record_offset:record_offset + 32])
        record_offset += 32

        # Parse data_sz
        data_sz = struct.unpack('<Q', record_data[record_offset:record_offset + 8])[0]
        record_offset += 8

        # Parse actual FEC data (up to data_sz from the fixed data array)
        # The data array starts at record_offset and can be up to FD_STORE_DATA_MAX (63985) bytes
        FD_STORE_DATA_MAX = 63985
        available_data_space = min(FD_STORE_DATA_MAX, len(record_data) - record_offset)
        actual_data_size = min(data_sz, available_data_space)

        fec_data = record_data[record_offset:record_offset + actual_data_size]

        # Move to next record
        offset += FD_STORE_FEC_SIZE

        # Limit data to specified number of bytes for inclusion in output
        original_data_sz = data_sz
        truncated_data = fec_data[:data_limit]

        # Create record dictionary with both fec_message and fd_store_fec_t
        # Use OrderedDict to preserve field order

        # Convert fd_store_fec_t data to space-separated format
        hex_bytes = binascii.hexlify(truncated_data).decode('ascii')
        data_hex_spaced = ' '.join(hex_bytes[i:i+2] for i in range(0, len(hex_bytes), 2))

        fec_record = OrderedDict([
            ('fec_message', OrderedDict([
                ('size', fec_msg_size),
                ('data', fec_msg_hex_spaced),
            ])),
            ('store_fec', OrderedDict([
                ('key', OrderedDict([
                    ('mr',   key['mr']),    # fd_hash_t mr (base58)
                    ('part', key['part']),  # ulong part
                ])),
                ('cmr',     cmr_hash_b58),     # fd_hash_t cmr (base58)
                ('next',    next_ptr),         # ulong next
                ('parent',  parent_ptr),       # ulong parent
                ('child',   child_ptr),        # ulong child
                ('sibling', sibling_ptr),      # ulong sibling
                ('data_sz', original_data_sz), # ulong data_sz
                ('data',    data_hex_spaced),  # uchar data[FD_STORE_DATA_MAX] (first 100 bytes, hex space-separated)
            ])),
        ])

        fec_records.append(fec_record)

    return OrderedDict([
        ('magic_header', binascii.hexlify(magic_header).decode('ascii')),
        ('fec_count', fec_count),
        ('records_parsed', len(fec_records)),
        ('source_file', os.path.basename(file_path)),
        ('file_size_bytes', len(data)),
        ('fec_records', fec_records)
    ])

def main():
    parser = argparse.ArgumentParser(description='Convert .feccap binary files (fec_message + fd_store_fec_t format) to organized JSON text format')
    parser.add_argument('feccap_file', help='Path to .feccap file to convert')
    parser.add_argument('--output', '-o', help='Output TXT file path (optional)')
    parser.add_argument('--compact', action='store_true', help='Use compact JSON output (default is pretty-printed)')
    parser.add_argument('--data-limit', type=int, default=100, help='Maximum bytes of FEC data to include per record (default: 100)')

    args = parser.parse_args()

    try:
        # Validate the .feccap file
        feccap_file = validate_feccap_file(args.feccap_file)
        print(f"Processing file: {feccap_file}")

        # Parse the .feccap file
        json_data = parse_feccap_file(feccap_file, args.data_limit)

        # Determine output file path
        if args.output:
            output_file = args.output
        else:
            # Use same base name but with .txt extension in same directory
            base_name = os.path.splitext(os.path.basename(feccap_file))[0]
            output_dir = os.path.dirname(feccap_file)
            output_file = os.path.join(output_dir, f"{base_name}.txt")

        # Write organized JSON output to text file
        with open(output_file, 'w') as f:
            # Add header comment for clarity
            f.write("# FEC Capture Data - Organized JSON Format (fec_message + fd_store_fec_t structure)\n")
            f.write(f"# Source file: {feccap_file}\n")
            f.write(f"# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total records: {json_data.get('records_parsed', 0)}\n")
            f.write(f"# File size: {json_data.get('file_size_bytes', 0)} bytes\n")
            f.write(f"# Record format: fec_message (160 bytes) + fd_store_fec_t (64128 bytes) = 64288 bytes total per record\n")
            f.write(f"# Data limit per record: {args.data_limit} bytes\n")
            f.write(f"# Hash encoding: 32-byte hashes shown as base58 (58 chars)\n")
            f.write("# " + "="*60 + "\n\n")

            # Write the JSON data (pretty-printed by default, compact if requested)
            # Note: sort_keys=False to preserve OrderedDict field ordering
            if args.compact:
                json.dump(json_data, f, separators=(',', ':'))
            else:
                json.dump(json_data, f, indent=2, sort_keys=False, ensure_ascii=False)

        print(f"Converted {json_data['records_parsed']} FEC records to organized JSON text format: {output_file}")
        print(f"Source file size: {json_data['file_size_bytes']} bytes")

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0

if __name__ == '__main__':
    exit(main())
