#!/bin/bash
# This script will take the path to build/ as an argument $1 and create the needed .fc
# files alongside the harnesses, then create the final zip at $2.
set -e

build_dir="$1"
output_zip="$2"

# Loop through each architecture, compiler, and fuzz target
for arch in haswell icelake; do
  for compiler in clang; do #aflgcc later
    for target_dir in "$build_dir/linux/$compiler/$arch/fuzz-test"/*; do
      target=$(basename "$target_dir")
      
      # Create the target directory structure
      target_path="targets/$arch/$compiler/$target"
      mkdir -p "$target_path"
      
      # Copy the fuzz target binary
      cp "$target_dir/$target" "$target_path/"
      
      # Create the .fc file
      fc_file="$target_path/$target.fc"
      cat > "$fc_file" <<EOL
{
  "fuzzTargetPath": "$target_path/$target",
  "covTargetPath": "",
  "lineage": "${target}_${arch}",
  "corpusGroup": "$target",
  "architecture": {
    "base": "x86_64",
    "ext": ["$([ "$arch" == "haswell" ] && echo "avx2" || echo "avx512")"]
  }
}
EOL
    done
  done
done

# Final Zip Archive creation is handled by the GitHub Action
# zip -r "$output_zip" targets/

echo "Fuzz targets and .fc files generated successfully!"