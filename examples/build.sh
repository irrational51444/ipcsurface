#!/usr/bin/env bash
# 把 examples 里的靶子打包、分析、压成报告。
# 需要：node / npx、rea、ipcsurface
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"
mkdir -p build

for target in static-asar dyn-asar obf-asar; do
  echo "==> $target"
  npx --yes @electron/asar pack "$target" "build/$target.asar"
  rea analyze-javascript-application "build/$target.asar" \
      --detail summary --evidence_output "build/ev-$target"
  ipcsurface "build/ev-$target" "build/$target.md"
  echo "--> build/$target.md"
done

echo
echo "两份报告都在 build/ 里，对着本目录的 README 核对。"
