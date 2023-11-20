#!/bin/bash

set -uEexo pipefail

# Generate indices

FUZZ_TARGETS=$(ls -1 build/pages/cov/fuzz/)
TEST_TARGETS=$(ls -1 build/pages/cov/test/)

# Generate fuzz index
for TARGET in $FEATURE_SETS_BUILT; do
  DIRS=$(echo build/pages/cov/fuzz/$TARGET/)
  PAGE="build/pages/cov/fuzz/$TARGET/index.html"
  echo "<!DOCTYPE html><html><head><meta charset="UTF-8"/></head><body><h1>Fuzz / $TARGET</h1>" > $PAGE
  echo '<ul>' >> $PAGE
  for FT in $(ls -1 $DIRS); do
    echo "<li><a href=\"./${FT}/index.html\">${FT}</a></li>" >> $PAGE
  done

  echo '</ul>' >> $PAGE
done
echo '</body></html>' >> $PAGE


PAGE="build/pages/cov/fuzz/index.html"
echo "<!DOCTYPE html><html><head><meta charset="UTF-8"/></head><body><h1>Fuzz /</h1>" > $PAGE
echo '<ul>' >> $PAGE
for TARGET in $FUZZ_TARGETS; do
  echo "<li><a href=\"./${TARGET}/index.html\">${TARGET}</a></li>" >> $PAGE
done
echo '</body></html>' >> $PAGE

PAGE="build/pages/cov/test/index.html"
echo "<!DOCTYPE html><html><head><meta charset="UTF-8"/></head><body><h1>Test /</h1>" > $PAGE
echo '<ul>' >> $PAGE
for TARGET in $TEST_TARGETS; do
  echo "<li><a href=\"./${TARGET}/index.html\">${TARGET}</a></li>" >> $PAGE
done
echo '</body></html>' >> $PAGE


# Generate cov index
cat <<EOS > build/pages/cov/index.html
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<title>🔥💃 Coverage</title>
</head>

<body>
<h1>🔥💃 Coverage</h1>
<h2>Links 🔗</h2>
<ul>
<li><a href="./test/index.html">Test Coverage</li>
<li><a href="./fuzz/index.html">Fuzzing Coverage</li>
</ul>
</body>

</html>
EOS

# Generate index
cat <<EOS > build/pages/index.html
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>🔥💃 Pages</title>
</head>

<body>
<h1>🔥💃 Pages</h1>
<p>From rev: $(git rev-parse HEAD)</p>
<h2>Links 🔗</h2>
<ul>
<li><a href="./cov/index.html">Coverage</li>
</ul>
</body>

</html>
EOS
