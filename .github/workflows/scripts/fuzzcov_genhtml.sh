#!/bin/bash

set -uEexo pipefail

mkdir -p build/pages/fuzzcov/

FUZZINDEX=build/pages/fuzzcov/index.html
cat > $FUZZINDEX <<EOS
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>🔥💃 FuzzCov</title></head>
<body>
    <h1>🔥💃 Fuzzing Coverage</h1>
EOS

echo "<p>From rev: $1</p><ul>" >> $FUZZINDEX

echo "<li><a href=\"./all\">all/</a></li>" >> $FUZZINDEX
genhtml --output-directory "build/pages/fuzzcov/all" build/fuzzcov/lcov/*.lcov

for f in build/fuzzcov/lcov/*.lcov
do
    BASE=$(basename "${f}")
    echo "<li><a href=\"./${BASE}\">${BASE}/</a></li>" >> $FUZZINDEX
    mkdir -p "build/pages/fuzzcov/${BASE}"
    genhtml --output-directory "build/pages/fuzzcov/${BASE}" $f
done

cat >> $FUZZINDEX <<EOS
</ul></body></html>
EOS
