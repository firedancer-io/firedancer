import subprocess

from geoip_db import update_dbip, read_version_mk, write_version_mk

VERSION_MK = 'src/app/fdctl/version.mk'

def main():
    update_dbip()

    version_major, version_minor, version_patch = read_version_mk(VERSION_MK)

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
    if '-' in solana_version.split('.')[2]:
        # prerelease
        solana_version_patch = int(solana_version.split('.')[3])
    else:
        # stable
        solana_version_patch = int(solana_version.split('.')[2])

    solana_version = f'{solana_version_major}{solana_version_minor:02d}{solana_version_patch:02d}'

    write_version_mk(VERSION_MK, version_major, version_minor, version_patch)

    subprocess.run(['git', 'add', 'src/disco/gui/dbip.bin.zst'], check=True)
    result = subprocess.run(['git', 'diff', '--cached', '--quiet', '--', 'src/disco/gui/dbip.bin.zst'])
    if result.returncode != 0:
        print(f"Creating commit and updating IP database")
        subprocess.run(['git', 'commit', '-m', f'Update IP databases'], check=True)
    else:
        print("No changes to geoip db. Skipping commit")

    print(f"Creating commit and tagging version v0.{version_minor}{version_patch:02d}.{solana_version}")
    subprocess.run(['git', 'add', VERSION_MK], check=True)
    subprocess.run(['git', 'commit', '-m', f'Increment version to v0.{version_minor}{version_patch:02d}.{solana_version}'], check=True)
    subprocess.run(['git', 'tag', f'v0.{version_minor}{version_patch:02d}.{solana_version}'], check=True)

if __name__ == '__main__':
    main()
