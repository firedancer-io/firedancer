# find_rpms.py is a helper script to find RPM download URLs


import argparse
import sys
import subprocess
import urllib.request
import xml.etree.ElementTree as ET


NAMESPACES = {
    "common": "http://linux.duke.edu/metadata/common",
    "repo": "http://linux.duke.edu/metadata/repo",
}


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def main():
    parser = argparse.ArgumentParser(description="Find RPM URLs")
    parser.add_argument("--fedora-version", type=str, default="43")
    parser.add_argument(
        "--mirror",
        type=str,
        default="https://dl.fedoraproject.org/pub/fedora/linux/releases/VERSION/Everything/ARCH/os",
    )
    parser.add_argument("--arch", type=str, default="x86_64")
    parser.add_argument("packages", nargs="*", type=str)
    args = parser.parse_args()
    if len(args.packages) == 0:
        return

    mirror = args.mirror.replace("VERSION", args.fedora_version).replace(
        "ARCH", args.arch
    )

    eprint("Reading repomd.xml")
    with urllib.request.urlopen(mirror + "/repodata/repomd.xml") as response:
        repomd = ET.parse(response)

    # Download primary.xml.zstd
    eprint("Reading primary.xml")
    primary_e = repomd.find(
        "repo:data[@type='primary']/repo:location", namespaces=NAMESPACES
    )
    primary_url = mirror + "/" + primary_e.get("href")
    with urllib.request.urlopen(primary_url) as response:
        primary_compressed = response.read()

    # Decompress using 'zstd -d' subprocess
    with subprocess.Popen(
        ["zstd", "-d"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    ) as proc:
        primary_xml, _ = proc.communicate(input=primary_compressed)
    primary = ET.fromstring(primary_xml)

    # Look up each package
    for package_name in args.packages:
        pkg_e = primary.find(
            f"common:package[common:name='{package_name}'][common:arch='{args.arch}']",
            namespaces=NAMESPACES,
        )
        if pkg_e is None:
            eprint(f"Package {package_name} not found in repository")
            sys.exit(1)
        location_e = pkg_e.find("common:location", namespaces=NAMESPACES)
        rpm_path = location_e.get("href")
        print(mirror + "/" + rpm_path)


if __name__ == "__main__":
    main()
