#!/usr/bin/env bash
# 把 examples 里的靶子打包、分析、压成报告。
# 需要：node / npx、rea、ipcsurface
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"
mkdir -p build

# bulk 和 map 都是生成的，不是手写的
python make-bulk.py
python make-map.py

for target in static-asar dyn-asar obf-asar obf2-asar bulk-asar native-asar; do
  echo "==> $target"
  npx --yes @electron/asar pack "$target" "build/$target.asar"

  # 粗扫：不用装 REA 也能跑
  ipcsurface "build/$target.asar" -o "build/$target.scan.md"

  # 语法级：要 REA
  if command -v rea >/dev/null 2>&1; then
    rea analyze-javascript-application "build/$target.asar" \
        --detail summary --evidence_output "build/ev-$target"
    ipcsurface "build/ev-$target" -o "build/$target.md"
  else
    echo "    没装 rea，跳过语法级"
  fi
done

echo
echo "报告都在 build/ 里，对着本目录的 README 核对。"
