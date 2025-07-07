#!/usr/bin/env python3

import struct
import socket
import os
import glob


def calculate_ipv4_checksum(header):
    """Calculate IPv4 header checksum"""
    # Set checksum field to 0
    header = header[:10] + b"\x00\x00" + header[12:]

    # Calculate checksum
    checksum = 0
    for i in range(0, len(header), 2):
        word = (header[i] << 8) + header[i + 1]
        checksum += word

    # Add carry bits
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # One's complement
    checksum = ~checksum & 0xFFFF
    return checksum


def parse_ethernet_header(data):
    """Parse Ethernet header (14 bytes)"""
    if len(data) < 14:
        raise ValueError("Packet too short for Ethernet header")

    dst_mac = data[0:6]
    src_mac = data[6:12]
    ethertype = struct.unpack("!H", data[12:14])[0]

    return dst_mac, src_mac, ethertype, data[14:]


def parse_ipv4_header(data):
    """Parse IPv4 header (variable length)"""
    if len(data) < 20:
        raise ValueError("Packet too short for IPv4 header")

    version_ihl = data[0]
    version = (version_ihl >> 4) & 0xF
    ihl = version_ihl & 0xF
    header_length = ihl * 4

    if version != 4:
        raise ValueError(f"Not an IPv4 packet (version={version})")

    if len(data) < header_length:
        raise ValueError("Packet too short for IPv4 header with options")

    # Parse header fields
    tos = data[1]
    total_length = struct.unpack("!H", data[2:4])[0]
    identification = struct.unpack("!H", data[4:6])[0]
    flags_fragoff = struct.unpack("!H", data[6:8])[0]
    ttl = data[8]
    protocol = data[9]
    checksum = struct.unpack("!H", data[10:12])[0]
    src_ip = data[12:16]
    dst_ip = data[16:20]
    options = data[20:header_length] if header_length > 20 else b""

    header = data[:header_length]
    payload = data[header_length:]

    return {
        "header": header,
        "version": version,
        "ihl": ihl,
        "header_length": header_length,
        "tos": tos,
        "total_length": total_length,
        "identification": identification,
        "flags_fragoff": flags_fragoff,
        "ttl": ttl,
        "protocol": protocol,
        "checksum": checksum,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "options": options,
        "payload": payload,
    }


def create_gre_header(protocol_type=0x0800):
    """Create basic GRE header (4 bytes)"""
    # Flags: no checksum, no key, no sequence number
    flags = 0x0000
    # Protocol type (0x0800 = IPv4)
    return struct.pack("!HH", flags, protocol_type)


def create_inner_ipv4_header(src_ip, dst_ip, payload_length, protocol=1, ttl=64):
    """Create inner IPv4 header"""
    version = 4
    ihl = 5  # 20 bytes header (no options)
    tos = 0
    total_length = 20 + payload_length
    identification = 0x1234  # You might want to randomize this
    flags_fragoff = 0x4000  # Don't fragment flag set
    header_checksum = 0  # Will be calculated later

    # Pack header without checksum
    header = struct.pack(
        "!BBHHHBBH4s4s",
        (version << 4) | ihl,  # Version + IHL
        tos,  # Type of Service
        total_length,  # Total Length
        identification,  # Identification
        flags_fragoff,  # Flags + Fragment Offset
        ttl,  # TTL
        protocol,  # Protocol
        header_checksum,  # Header Checksum (0 for now)
        src_ip,  # Source IP
        dst_ip,  # Destination IP
    )

    # Calculate and insert checksum
    checksum = calculate_ipv4_checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]

    return header


def inject_gre_and_inner_ip(
    packet_data
):
    """Inject GRE header and inner IPv4 header into packet"""

    # Parse Ethernet header
    dst_mac, src_mac, ethertype, ip_data = parse_ethernet_header(packet_data)

    if ethertype != 0x0800:
        raise ValueError(f"Not an IPv4 packet (EtherType=0x{ethertype:04x})")

    # Parse outer IPv4 header
    ipv4_info = parse_ipv4_header(ip_data)

    inner_src_ip = ipv4_info['src_ip']
    inner_dst_ip = ipv4_info['dst_ip']

    print(inner_src_ip)
    print(inner_dst_ip)


    # Create GRE header
    gre_header = create_gre_header()

    # Convert IP addresses to bytes if they're strings
    if isinstance(inner_src_ip, str):
        inner_src_ip = socket.inet_aton(inner_src_ip)
    if isinstance(inner_dst_ip, str):
        inner_dst_ip = socket.inet_aton(inner_dst_ip)

    # Create inner IPv4 header
    inner_ipv4_header = create_inner_ipv4_header(
        inner_src_ip,
        inner_dst_ip,
        len(ipv4_info["payload"]),
        protocol=ipv4_info["protocol"],  # Keep original protocol
    )

    # Calculate new total length for outer IPv4 header
    gre_and_inner_length = len(gre_header) + len(inner_ipv4_header)
    new_outer_total_length = (
        ipv4_info["header_length"] + gre_and_inner_length + len(ipv4_info["payload"])
    )

    # Create new outer IPv4 header with updated length and protocol (GRE = 47)
    new_outer_header = struct.pack(
        "!BBHHHBBH4s4s",
        (ipv4_info["version"] << 4) | ipv4_info["ihl"],
        ipv4_info["tos"],
        new_outer_total_length,
        ipv4_info["identification"],
        ipv4_info["flags_fragoff"],
        ipv4_info["ttl"],
        47,  # GRE protocol
        0,  # Checksum (will be calculated)
        inner_src_ip,
        inner_dst_ip,
    )

    # Add options if present
    if ipv4_info["options"]:
        new_outer_header += ipv4_info["options"]

    # Calculate outer header checksum
    outer_checksum = calculate_ipv4_checksum(new_outer_header)
    new_outer_header = (
        new_outer_header[:10]
        + struct.pack("!H", outer_checksum)
        + new_outer_header[12:]
    )

    # Reassemble the packet
    ethernet_header = dst_mac + src_mac + struct.pack("!H", ethertype)
    new_packet = (
        ethernet_header
        + new_outer_header
        + gre_header
        + inner_ipv4_header
        + ipv4_info["payload"]
    )

    return new_packet


def process_packet_files(
    input_pattern, output_dir, inner_src_ip="10.0.0.1", inner_dst_ip="10.0.0.2"
):
    """Process multiple packet files"""

    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    files = glob.glob(input_pattern)
    if not files:
        print(f"No files found matching pattern: {input_pattern}")
        return

    for input_file in files:
        try:
            print(f"Processing {input_file}...")

            # Read original packet
            with open(input_file, "rb") as f:
                packet_data = f.read()

            # Process packet
            modified_packet = inject_gre_and_inner_ip(packet_data)

            # Write modified packet
            base = os.path.basename(input_file)
            stem, ext = os.path.splitext(base)
            output_file = os.path.join(output_dir, f"{stem}_gre{ext}")
            with open(output_file, "wb") as f:
                f.write(modified_packet)

            print(
                f"  Created {output_file} ({len(packet_data)} -> {len(modified_packet)} bytes)"
            )

        except Exception as e:
            print(f"  Error processing {input_file}: {e}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Inject GRE header and inner IPv4 header into packets"
    )
    parser.add_argument(
       "input_pattern", help='Input file pattern (e.g., "packets/*.bin")'
    )
    parser.add_argument("-o", "--output-dir", default="output", help="Output directory")
    args = parser.parse_args()

    process_packet_files(
        args.input_pattern, args.output_dir
    )


if __name__ == "__main__":
    main()
