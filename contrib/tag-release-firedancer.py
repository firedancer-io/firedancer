import subprocess

from geoip_db import update_dbip, read_version_mk, write_version_mk

VERSION_MK = 'src/app/firedancer/version.mk'

def main():
    update_dbip()

    version_major, version_minor, version_patch = read_version_mk(VERSION_MK, prefix='FD_VERSION')

    git_branch = subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], stdout=subprocess.PIPE, check=True)
    git_branch = git_branch.stdout.decode('utf-8').strip()

    if git_branch != f'v{version_major}.{version_minor}':
        print('Error: branch name must match the major.minor version in version.mk (like v1.1)')
        exit(1)

    version_patch += 1

    write_version_mk(VERSION_MK, version_major, version_minor, version_patch, prefix='FD_VERSION')

    subprocess.run(['git', 'add', 'src/disco/gui/dbip.bin.zst'], check=True)
    result = subprocess.run(['git', 'diff', '--cached', '--quiet', '--', 'src/disco/gui/dbip.bin.zst'])
    if result.returncode != 0:
        print(f"Creating commit and updating IP database")
        subprocess.run(['git', 'commit', '-m', f'Update IP databases'], check=True)
    else:
        print("No changes to geoip db. Skipping commit")

    version = f'v{version_major}.{version_minor}.{version_patch}'
    print(f"Creating commit and tagging version {version}")
    subprocess.run(['git', 'add', VERSION_MK], check=True)
    subprocess.run(['git', 'commit', '-m', f'Increment version to {version}'], check=True)
    subprocess.run(['git', 'tag', version], check=True)

if __name__ == '__main__':
    main()
