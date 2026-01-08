import urllib.request
import gzip
import csv
import struct
import tempfile
import argparse
from pathlib import Path
from typing import BinaryIO, Optional, Callable

import netaddr
import zstandard

# The following constants much be matching in the C source code.
FD_GUI_GEOIP_ZSTD_COMPRESSION_LEVEL = 19
FD_GUI_GEOIP_ZSTD_WINDOW_LOG = 23
FD_GUI_GEOIP_MAX_CITY_NAME_SZ = 80
FD_GUI_GEOIP_MAX_CITY_CNT = 160000
FD_GUI_GEOIP_MAX_COUNTRY_CNT = 254
FD_GUI_GEOIP_DBIP_MAX_NODES = 2**24

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

    with open(output_path, 'wb') as f:
        f.write(struct.pack('<Q', len(country_codes)))
        for cc in sorted(country_codes):
            f.write(cc.encode('ascii'))

        f.write(struct.pack('<Q', len(city_names)))
        for cy in sorted(city_names.keys()):
            f.write(cy.encode('ascii'))

        records = sum(len(ips) for _, ips in city_names_coalesced.items())
        assert(records <= FD_GUI_GEOIP_DBIP_MAX_NODES)
        f.write(struct.pack('<Q', records))

        for cy, ips in city_names_coalesced.items():
            for ip in ips:
                f.write(struct.pack('>I', ip.network))
                f.write(struct.pack('<B', ip.prefixlen))
                f.write(struct.pack('<B', country_to_index[city_to_country[cy]]))
                f.write(struct.pack('<I', city_to_index[cy]))

    print(f"Converted {records} records with {len(country_codes)} country codes")

def update_db(url: str, output_path: Path, processor: Callable[[Path, Path], None]) -> None:
    req = urllib.request.Request(url=url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'})

    with tempfile.TemporaryDirectory() as tmpdir:
        with urllib.request.urlopen(req) as f:
            with gzip.open(f, 'rb') as f_in:
                (Path(tmpdir) / "db.csv").write_bytes(f_in.read())

        processor(Path(tmpdir) / "db.csv", Path(tmpdir) / "db.bin")
        compressor = zstandard.ZstdCompressor(level=FD_GUI_GEOIP_ZSTD_COMPRESSION_LEVEL)
        output_path.write_bytes(compressor.compress((Path(tmpdir) / "db.bin").read_bytes()))

def main():
    print("Updating dbip.bin (this will take ~2-5 minutes)")
    dbip_url = "https://github.com/sapics/ip-location-db/raw/refs/heads/main/dbip-city/dbip-city-ipv4.csv.gz"
    update_db(dbip_url, Path('src/disco/gui/dbip.bin.zst'), convert_dbip)

    with open('src/app/fdctl/version.mk', 'r') as f:
        lines = f.readlines()

    version_major = None
    version_minor = None
    version_patch = None
    for line in lines:
        if line.startswith('VERSION_MAJOR'):
            version_major = int(line.split(':=')[1].strip())
        elif line.startswith('VERSION_MINOR'):
            version_minor = int(line.split(':=')[1].strip())
        elif line.startswith('VERSION_PATCH'):
            version_patch = int(line.split(':=')[1].strip())
        else:
            print('Error: version.mk file is not well formatted')
            exit(1)

    if version_major is None or version_minor is None or version_patch is None:
        print('Error: version.mk file is not well formatted')
        exit(1)

    # Now retrieve the git branch like git rev-parse --abbrev-ref HEAD
    import subprocess
    git_branch = subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], stdout=subprocess.PIPE, check=True)
    git_branch = git_branch.stdout.decode('utf-8').strip()

    if not git_branch.startswith('v0.'):
        print('Error: branch name must be formatted like v0.x')
        exit(1)

    branch_version_minor = int(git_branch.split('.')[1])
    if branch_version_minor != version_minor:
        print('Error: branch name does not match the minor version in version.mk')
        exit(1)

    version_patch += 1
    if version_patch >= 100:
        print('Error: version patch number is too high')
        exit(1)

    solana_version = subprocess.run(['cargo', 'pkgid'], cwd='agave/validator', stdout=subprocess.PIPE, check=True)
    solana_version = solana_version.stdout.decode('utf-8').strip().split('@')[1]
    solana_version_major = int(solana_version.split('.')[0])
    solana_version_minor = int(solana_version.split('.')[1])
    solana_version_patch = int(solana_version.split('.')[2])

    solana_version = f'{solana_version_major}{solana_version_minor:02d}{solana_version_patch:02d}'

    with open('src/app/fdctl/version.mk', 'w') as f:
        f.write('VERSION_MAJOR := {}\n'.format(version_major))
        f.write('VERSION_MINOR := {}\n'.format(version_minor))
        f.write('VERSION_PATCH := {}\n'.format(version_patch))

    try:
        subprocess.run(
            ['git', 'diff-index', '--quiet', 'HEAD', '--', 'src/disco/gui/dbip.bin.zst'],
            check=True  # This will raise CalledProcessError if the exit code is non-zero (i.e. there are changes)
        )
        print("No staged changes for geoip database, skipping commit")
    except subprocess.CalledProcessError:
        print(f"Creating commit and updating IP database")
        subprocess.run(['git', 'add', 'src/disco/gui/dbip.bin.zst'], check=True)
        subprocess.run(['git', 'commit', '-m', f'Update IP databases'], check=True)

    print(f"Creating commit and tagging version v0.{version_minor}{version_patch:02d}.{solana_version}")
    subprocess.run(['git', 'add', 'src/app/fdctl/version.mk'], check=True)
    subprocess.run(['git', 'commit', '-m', f'Increment version to v0.{version_minor}{version_patch:02d}.{solana_version}'], check=True)
    subprocess.run(['git', 'tag', f'v0.{version_minor}{version_patch:02d}.{solana_version}'], check=True)

if __name__ == '__main__':
    main()
