set -e
s=$(curl -s --max-redirs 0 $1)
wget -q --trust-server-names $1
echo "${s:1}"
