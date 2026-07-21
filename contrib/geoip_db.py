import urllib.request
import gzip
import csv
import struct
import tempfile
from pathlib import Path
from typing import Callable

import netaddr
import zstandard

# The following constants much be matching in the C source code.
FD_GUI_GEOIP_ZSTD_COMPRESSION_LEVEL = 19
FD_GUI_GEOIP_ZSTD_WINDOW_LOG = 23
FD_GUI_GEOIP_MAX_CITY_NAME_SZ = 80
FD_GUI_GEOIP_MAX_CITY_CNT = 160000
FD_GUI_GEOIP_MAX_COUNTRY_CNT = 254
FD_GUI_GEOIP_BIN_MAX = 128 * 2**20

assert( zstandard.ZstdCompressionParameters.from_level(FD_GUI_GEOIP_ZSTD_COMPRESSION_LEVEL).window_log == FD_GUI_GEOIP_ZSTD_WINDOW_LOG )

def convert_dbip(input_path: Path, output_path: Path) -> None:
    country_codes = set()
    city_to_country = {}
    city_names = {} # city to cidrs
    with open(input_path, 'r') as r:
        reader = csv.DictReader(r, fieldnames=['ip_range_start', 'ip_range_end', 'country_code', 'state1', 'state2', 'city', 'postcode', 'latitude', 'longitude', 'timezone'])
        for row in reader:
            try:
                netaddr.IPAddress(row['ip_range_start'], version=4)
                netaddr.IPAddress(row['ip_range_end'], version=4)
            except netaddr.AddrFormatError:
                continue
            assert len(row['country_code']) == 2
            country_codes.add(row['country_code'])

            city_cstr = row['city'].encode('ascii', 'replace').decode('ascii') + "\0"
            assert len(city_cstr) <= FD_GUI_GEOIP_MAX_CITY_NAME_SZ
            city_to_country[city_cstr] = row['country_code']

            city_names.setdefault(city_cstr, [])
            city_names[city_cstr].extend(netaddr.iprange_to_cidrs(row['ip_range_start'], row['ip_range_end']))

    assert len(country_codes) <= FD_GUI_GEOIP_MAX_COUNTRY_CNT, f"Too many country codes ({len(country_codes)}) to fit in a byte (max 254)"
    country_to_index = {cc: idx for idx, cc in enumerate(sorted(country_codes))}

    assert len(city_names) <= FD_GUI_GEOIP_MAX_CITY_CNT, f"Too many city names ({len(city_names)})"
    city_names_coalesced = {cy: list(netaddr.cidr_merge(ips)) for cy, ips in city_names.items()}
    city_to_index = {cy: idx for idx, cy in enumerate(sorted(city_names.keys()))}

    # Flatten the (possibly nested) CIDR records into disjoint segments
    # partitioning the whole IPv4 space, with longest-prefix-match
    # semantics: sort by (network, prefixlen), then sweep with a stack
    # of open ranges.  Segment i covers [start[i], start[i+1]); country
    # 255 / city 0xFFFFFFFF mean unmapped.  Lookup in the validator is
    # then a binary search over start[], and startup is a single
    # streaming decompress (see fd_gui_peers.h).
    UNKNOWN = (255, 0xFFFFFFFF)
    records = []
    for cy, ips in city_names_coalesced.items():
        for ip in ips:
            # int, not IPAddress: ranges ending at 2**32 overflow IPAddress
            records.append((int(ip.network), ip.prefixlen, country_to_index[city_to_country[cy]], city_to_index[cy]))
    records.sort()

    segments = []  # (start, country_idx, city_idx)
    def emit(start, country, city):
        if start >= 2**32:  # zero-width tail (a range ended exactly at 2**32)
            return
        if segments and segments[-1][0] == start:
            segments[-1] = (start, country, city)
            return
        if segments and segments[-1][1:] == (country, city):
            return
        segments.append((start, country, city))

    stack = [(2**32, *UNKNOWN)]  # (end_exclusive, country, city)
    emit(0, *UNKNOWN)
    for network, prefixlen, country, city in records:
        end = network + 2**(32 - prefixlen)
        while stack[-1][0] <= network:
            closed_end = stack.pop()[0]
            emit(closed_end, stack[-1][1], stack[-1][2])
        stack.append((end, country, city))
        emit(network, country, city)
    while len(stack) > 1:
        closed_end = stack.pop()[0]
        emit(closed_end, stack[-1][1], stack[-1][2])

    with open(output_path, 'wb') as f:
        f.write(struct.pack('<Q', len(country_codes)))
        for cc in sorted(country_codes):
            f.write(cc.encode('ascii'))

        f.write(struct.pack('<Q', len(city_names)))
        for cy in sorted(city_names.keys()):
            f.write(cy.encode('ascii'))

        # 4-byte align so the validator uses the arrays in place
        f.write(b'\0' * (-f.tell() % 4))
        f.write(struct.pack('<Q', len(segments)))
        for start, _, _ in segments:
            f.write(struct.pack('<I', start))
        for _, country, _ in segments:
            f.write(struct.pack('<B', country))
        f.write(b'\0' * (-f.tell() % 4))
        for _, _, city in segments:
            f.write(struct.pack('<I', city))

        assert f.tell() <= FD_GUI_GEOIP_BIN_MAX

    print(f"Converted {len(records)} records into {len(segments)} segments with {len(country_codes)} country codes")

def update_db(url: str, output_path: Path, processor: Callable[[Path, Path], None]) -> None:
    req = urllib.request.Request(url=url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'})

    with tempfile.TemporaryDirectory() as tmpdir:
        with urllib.request.urlopen(req) as f:
            with gzip.open(f, 'rb') as f_in:
                (Path(tmpdir) / "db.csv").write_bytes(f_in.read())

        processor(Path(tmpdir) / "db.csv", Path(tmpdir) / "db.bin")
        compressor = zstandard.ZstdCompressor(level=FD_GUI_GEOIP_ZSTD_COMPRESSION_LEVEL)
        output_path.write_bytes(compressor.compress((Path(tmpdir) / "db.bin").read_bytes()))

def update_dbip() -> None:
    print("Updating dbip.bin (this will take ~2-5 minutes)")
    dbip_url = "https://github.com/sapics/ip-location-db/releases/download/latest/dbip-city-ipv4.csv.gz"
    update_db(dbip_url, Path('src/disco/gui/dbip.bin.zst'), convert_dbip)

def read_version_mk(path: str, prefix: str = 'VERSION'):
    with open(path, 'r') as f:
        lines = f.readlines()

    version_major = None
    version_minor = None
    version_patch = None
    for line in lines:
        if line.startswith(f'{prefix}_MAJOR'):
            version_major = int(line.split(':=')[1].strip())
        elif line.startswith(f'{prefix}_MINOR'):
            version_minor = int(line.split(':=')[1].strip())
        elif line.startswith(f'{prefix}_PATCH'):
            version_patch = int(line.split(':=')[1].strip())
        else:
            print('Error: version.mk file is not well formatted')
            exit(1)

    if version_major is None or version_minor is None or version_patch is None:
        print('Error: version.mk file is not well formatted')
        exit(1)

    return version_major, version_minor, version_patch

def write_version_mk(path: str, version_major: int, version_minor: int, version_patch: int, prefix: str = 'VERSION') -> None:
    with open(path, 'w') as f:
        f.write(f'{prefix}_MAJOR := {version_major}\n')
        f.write(f'{prefix}_MINOR := {version_minor}\n')
        f.write(f'{prefix}_PATCH := {version_patch}\n')
