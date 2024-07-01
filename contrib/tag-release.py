def main():
    version_txt = open('src/app/fdctl/version.txt', 'r').read().strip()
    version_parts = version_txt.split('.')
    version_major = int(version_parts[0])
    version_minor = int(version_parts[1])

    # Now retrieve the git branch like git rev-parse --abbrev-ref HEAD
    import subprocess
    git_branch = subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], stdout=subprocess.PIPE, check=True)
    git_branch = git_branch.stdout.decode('utf-8').strip()

    if not git_branch.startswith(f'v{version_major}.'):
        print(f'Error: branch name must be formatted like v{version_major}.x')
        exit(1)

    branch_version_minor = int(git_branch.split('.')[1])
    if branch_version_minor != version_minor:
        print('Error: branch name does not match the minor version in version.mk')
        exit(1)

    version_patch += 1
    if version_patch >= 100:
        print('Error: version patch number is too high')
        exit(1)

    solana_version = subprocess.run(['cargo', 'pkgid'], cwd='solana/validator', stdout=subprocess.PIPE, check=True)
    solana_version = solana_version.stdout.decode('utf-8').strip().split('@')[1]
    solana_version_major = int(solana_version.split('.')[0])
    solana_version_minor = int(solana_version.split('.')[1])
    solana_version_patch = int(solana_version.split('.')[2])

    solana_version = f'{solana_version_major}{solana_version_minor:02d}{solana_version_patch:02d}'

    print(f"Creating commit and tagging version v{version_major}.{version_minor}{version_patch:02d}.{solana_version}")
    subprocess.run(['git', 'commit', '-m', f'Increment version to v{version_major}.{version_minor}{version_patch:02d}.{solana_version}'], check=True)
    subprocess.run(['git', 'tag', f'v{version_major}.{version_minor}{version_patch:02d}.{solana_version}'], check=True)

if __name__ == '__main__':
    main()
