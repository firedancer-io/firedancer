#!/usr/bin/env bash

# Runs the given command with increased capabilities.
# Expects cwd to be the repository root.

if [[ $# == 0 ]]
then
    >&2 echo "usage: run-ulimit.sh <arguments...>"
    exit 1
fi

disable_pam_limits () {
    cat <<EOF > /etc/security/limits.conf
* hard memlock unlimited
* hard nice -20
* hard rtprio unlimited
EOF
}

increase_ulimits () {
    ulimit -H -m unlimited -l unlimited
    ulimit -S -m unlimited -l unlimited
}

if [[ "$(id -u)" -ne "0" ]]
then
    # Recurse into else branch of this if statement.
    exec sudo -i -- /usr/bin/env "$(realpath "$0")" "$PATH" "$PWD" "$@"
else
    # Use superuser privileges to increase ulimits
    if [[ ! -z "$CI" ]]; then disable_pam_limits; fi
    increase_ulimits
    # We are the target of recursion. Drop privileges.
    if [[ -z "$SUDO_USER" ]]; then
        >&2 echo "run-ulimit.sh should be called via sudo -E"
        exit 1
    fi
    prlimit
    # Restore env from given args.
    ORIG_PATH="$1"
    ORIG_PWD="$2"
    shift 2
    # Dispatch new user login shell.
    exec sudo -i -u "$SUDO_USER" -- /usr/bin/env "PATH=$ORIG_PATH" sh -c "cd $(printf "%q" "$ORIG_PWD") && $(printf "%q " "$@")"
fi
