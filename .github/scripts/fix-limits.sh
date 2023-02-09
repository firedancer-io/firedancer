#!/usr/bin/env bash

cat <<EOF > /etc/security/limits.conf
* hard memlock unlimited
* hard nice -20
* hard rtprio unlimited
EOF
