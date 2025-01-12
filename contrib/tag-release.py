def main():
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

    print(f"Creating commit and tagging version v0.{version_minor}{version_patch:02d}.{solana_version}")
    subprocess.run(['git', 'add', 'src/app/fdctl/version.mk'], check=True)
    subprocess.run(['git', 'commit', '-m', f'Increment version to v0.{version_minor}{version_patch:02d}.{solana_version}'], check=True)
    subprocess.run(['git', 'tag', f'v0.{version_minor}{version_patch:02d}.{solana_version}'], check=True)

if __name__ == '__main__':
    main()
