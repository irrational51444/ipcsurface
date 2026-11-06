#!/usr/bin/env bash
# 冒烟：把每条命令都真跑一遍，看有没有哪条是坏的。
#
# 用法（在仓库根目录）：
#   bash scripts/smoke.sh                     # 用 python ipcsurface.py
#   bash scripts/smoke.sh ipcsurface          # 用装好的那个
#
# 需要先有 examples/build/*.asar（跑一次 examples/build.sh 就有），
# 以及一份 Evidence：默认自己找 ev-*，也可以用 EVIDENCE=... 指定。
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
    printf '[FAIL] %s（退出码 %s）\n' "$name" "$?"
    fail=$((fail + 1))
  fi
}

# 要求特定的退出码。门禁这种东西，对了才算对。
run_code() {
  local name=$1 expect=$2
  shift 2
  "$@" >/dev/null 2>&1
  local got=$?
  if [ "$got" -eq "$expect" ]; then
    printf '[OK]   %s（退出码 %s）\n' "$name" "$got"
    pass=$((pass + 1))
  else
    printf '[FAIL] %s（要 %s，得到 %s）\n' "$name" "$expect" "$got"
    fail=$((fail + 1))
  fi
}

asm=$(ls examples/build/*.asar 2>/dev/null | head -1)
dyn=$(ls examples/build/dyn-asar.asar 2>/dev/null | head -1)
obf=$(ls examples/build/obf-asar.asar 2>/dev/null | head -1)
mapfile=$(ls examples/map.asar 2>/dev/null | head -1)
ev=${EVIDENCE:-$(find . -maxdepth 4 \( -type f -o -type d \) -name 'ev-*' -size +1k 2>/dev/null | head -1)}

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

if [ -n "$dyn" ]; then
  run_code "dyn 里有算出来的名字，不该拦" 0 $cmd "$dyn" --fail-on high -o /tmp/smoke-dyn.md
fi

if [ -n "$obf" ]; then
  run_code "obf 有强混淆指纹，应该拦" 2 $cmd "$obf" --fail-on high -o /tmp/smoke-obf.md
fi

if [ -n "$mapfile" ]; then
  run "带 sourcemap 的包" $cmd "$mapfile" -o /tmp/smoke-map.md
fi

if [ -n "$ev" ]; then
  run "证据出 md" $cmd "$ev" -o /tmp/smoke-4.md
  run "写基线" $cmd "$ev" --write-baseline /tmp/smoke-base.json -o /tmp/smoke-5.md
  run "读基线" $cmd "$ev" --baseline /tmp/smoke-base.json -o /tmp/smoke-6.md
else
  echo "  （没找到 Evidence，跳过语法级那几项）"
fi

run_code "不存在的文件" 1 $cmd nope.asar
run_code "给一个目录" 1 $cmd examples
run_code "不认识的文本" 1 $cmd README.md

printf -- '---- %d 通过 / %d 失败 ----\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
