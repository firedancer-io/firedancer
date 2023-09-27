#!/bin/bash

set -uEexo pipefail

# Generate indices

FUZZ_TARGETS=$(ls -1 build/pages/cov/fuzz/)
TEST_TARGETS=$(ls -1 build/pages/cov/test/)

# Generate fuzz index
for TARGET in $FEATURE_SETS_BUILT; do
  DIRS=$(echo build/pages/cov/fuzz/$TARGET/)
  PAGE="build/pages/cov/fuzz/$TARGET/index.html"
  echo "<h1>Fuzz / $TARGET</h1>" > $PAGE
  echo '<ul>' >> $PAGE
  for FT in $(ls -1 $DIRS); do
    echo "<li><a href=\"./${FT}\">${FT}</a></li>" >> $PAGE
  done

  echo '</ul>' >> $PAGE
done


PAGE="build/pages/cov/fuzz/index.html"
echo "<h1>Fuzz /</h1>" > $PAGE
echo '<ul>' >> $PAGE
for TARGET in $FUZZ_TARGETS; do
  echo "<li><a href=\"./${TARGET}\">${TARGET}</a></li>" >> $PAGE
done
echo '</ul>' >> $PAGE

PAGE="build/pages/cov/test/index.html"
echo "<h1>Test /</h1>" > $PAGE
echo '<ul>' >> $PAGE
for TARGET in $TEST_TARGETS; do
  echo "<li><a href=\"./${TARGET}\">${TARGET}</a></li>" >> $PAGE
done
echo '</ul>' >> $PAGE


# Generate cov index
cat <<EOS > build/pages/cov/index.html
<!DOCTYPE html>
<html>
<head>
<title>🔥💃 Coverage</title>
</head>

<body>
<h1>🔥💃 Coverage</h1>
<h2>Links 🔗</h2>
<ul>
<li><a href="./test/">Test Coverage</li>
<li><a href="./fuzz/">Fuzzing Coverage</li>
</ul>
</body>

</html>
EOS

# Generate index
cat <<EOS > build/pages/index.html
<!DOCTYPE html>
<html>
<head>
<title>🔥💃 Pages</title>
</head>

<body>
<h1>🔥💃 Pages</h1>
<p>From rev: $(git rev-parse HEAD)</p>
<h2>Links 🔗</h2>
<ul>
<li><a href="./cov/">Coverage</li>
</ul>
</body>

</html>
EOS
