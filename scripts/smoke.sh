#!/usr/bin/env bash
# 冒烟：把每条命令都真跑一遍，看有没有哪条是坏的。
#
# 用法（在仓库根目录）：
#   bash scripts/smoke.sh
#
# 需要先有 examples/build/*.asar（跑一次 examples/build.sh 就有），
# 以及一份 Evidence 目录：默认读 $EVIDENCE，没设就跳过那几项。
set -uo pipefail

cmd=${1:-python ipcsurface.py}
pass=0
fail=0

run() {
  local name=$1
  shift
  if "$@" >/dev/null 2>&1; then
    printf '[OK]   %s\n' "$name"
    pass=$((pass + 1))
  else
    printf '[FAIL] %s\n' "$name"
    fail=$((fail + 1))
  fi
}

# 期望失败的，反过来判
run_fail() {
  local name=$1
  shift
  if "$@" >/dev/null 2>&1; then
    printf '[FAIL] %s（本该失败却过了）\n' "$name"
    fail=$((fail + 1))
  else
    printf '[OK]   %s\n' "$name"
    pass=$((pass + 1))
  fi
}

asm=$(ls examples/build/*.asar 2>/dev/null | head -1)
ev=${EVIDENCE:-$(find . -maxdepth 4 \( -type f -o -type d \) -name 'ev-*' 2>/dev/null | head -1)}

run "版本" $cmd --version
run "帮助" $cmd --help

if [ -n "$asm" ]; then
  run "asar 出 md" $cmd "$asm" -o /tmp/smoke-1.md
  run "asar 出 json" $cmd "$asm" --format json -o /tmp/smoke-2.json
  run "asar 比版本" $cmd "$asm" --diff "$asm" -o /tmp/smoke-3.md
  run "深目录自动建" $cmd "$asm" -o /tmp/smoke/deep/out.md
else
  echo "  （没有 examples/build/*.asar，先跑 examples/build.sh）"
fi

if [ -n "$ev" ]; then
  run "证据出 md" $cmd "$ev" -o /tmp/smoke-4.md
  run "写基线" $cmd "$ev" --write-baseline /tmp/smoke-base.json -o /tmp/smoke-5.md
  run "读基线" $cmd "$ev" --baseline /tmp/smoke-base.json -o /tmp/smoke-6.md
else
  echo "  （没找到 Evidence 目录，跳过语法级那几项）"
fi

run_fail "不存在的文件" $cmd nope.asar
run_fail "给一个目录" $cmd examples

printf -- '---- %d 通过 / %d 失败 ----\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
