import urllib.request
import ipaddress
import gzip
import csv
import struct
import tempfile
from pathlib import Path
from typing import BinaryIO

def convert_ipinfo(input_path: Path, output_path: Path) -> None:
    country_codes = set()
    with open(input_path, 'r') as r:
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

    with open(input_path, 'r') as r:
        reader = csv.DictReader(r)
        with open(output_path, 'wb') as f:
            f.write(struct.pack('<Q', len(country_codes)))
            for cc in sorted(country_codes):
                f.write(cc.encode('ascii'))

            records = 0
            for row in reader:
                try:
                    network = ipaddress.IPv4Network(row['network'])
                except ipaddress.AddressValueError:
                    continue

                country_idx = country_to_index[row['country_code']]

                f.write(struct.pack('>I', int(network.network_address)))
                f.write(struct.pack('<B', network.prefixlen))
                f.write(struct.pack('<B', country_idx))
                records += 1

    if records > 1e22:
        raise AssertionError("Number of records exceeds IPINFO_MAX_NODES")

    print(f"Converted {records} records with {len(country_codes)} country codes")

def main():
    ipinfo_access_token = input("Input your ipinfo API token. You can retrieve it by visiting https://ipinfo.io/dashboard/token and logging in with your github account.\n")
    url = f"https://ipinfo.io/data/ipinfo_lite.csv.gz?token={ipinfo_access_token}"

    req = urllib.request.Request(url=url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'})
    with urllib.request.urlopen(req) as f:
        with tempfile.TemporaryDirectory() as tmpdir:
            with gzip.open(f, 'rb') as f_in:
                f_out = (Path(tmpdir) / "ipinfo.csv")
                f_out.write_bytes(f_in.read())
            convert_ipinfo(f_out, Path('src/disco/gui/ipinfo.bin'))

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

    print(f"Creating commit and updating ipinfo.bin")
    subprocess.run(['git', 'add', 'src/disco/gui/ipinfo.bin'], check=True)
    subprocess.run(['git', 'commit', '-m', f'Update ipinfo.bin'], check=True)

    print(f"Creating commit and tagging version v0.{version_minor}{version_patch:02d}.{solana_version}")
    subprocess.run(['git', 'add', 'src/app/fdctl/version.mk'], check=True)
    subprocess.run(['git', 'commit', '-m', f'Increment version to v0.{version_minor}{version_patch:02d}.{solana_version}'], check=True)
    subprocess.run(['git', 'tag', f'v0.{version_minor}{version_patch:02d}.{solana_version}'], check=True)

if __name__ == '__main__':
    main()
