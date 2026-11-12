#!/usr/bin/env bash
# 改完就跑这一条。三道闸，任何一道红就停。
#
#   bash scripts/verify.sh
#
# 1. 单元用例
# 2. 冒烟（每条命令真跑一遍）
# 3. 自查（版本、文档、真包、输入侧、输出侧、工作区）
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

fail=0

echo "== 1/4 单元用例 =="
# 管道会把退出码换成 tail 的，必须显式取左边那个
python -m unittest discover -s tests > /tmp/verify-unit.log 2>&1
unit=$?
tail -3 /tmp/verify-unit.log
if [ "$unit" -eq 0 ]; then
  echo "   通过"
else
  echo "   没过（退出码 $unit，完整输出在 /tmp/verify-unit.log）"
  fail=1
fi

echo "== 2/4 冒烟 =="
bash scripts/smoke.sh > /tmp/verify-smoke.log 2>&1
smoke=$?
tail -2 /tmp/verify-smoke.log
if [ "$smoke" -eq 0 ]; then
  echo "   通过"
else
  echo "   没过（退出码 $smoke，完整输出在 /tmp/verify-smoke.log）"
  fail=1
fi

echo "== 3/4 自查 =="
python scripts/selfcheck.py || fail=1

echo "== 4/4 污点尺子 =="
python scripts/taint_ruler.py || fail=1

# 校准基线是「本机门禁」：要扫真包（obsidian/dsh/vivo 的绝对路径），CI 上没有。
# 默认跳过，设 IPCSURFACE_CALIBRATE=1 才跑（约 2 分钟）。
if [ -f tests/golden/calibration.json ]; then
  if [ "${IPCSURFACE_CALIBRATE:-0}" = "1" ]; then
    echo
    echo "== 校准基线 =="
    python scripts/calibration.py --baseline tests/golden/calibration.json || fail=1
  else
    echo "   校准基线存在，跳过（设 IPCSURFACE_CALIBRATE=1 才跑，约 2 分钟）"
  fi
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "四道闸全绿（单元用例 / 冒烟 / 自查 / 污点尺子）。"
else
  echo "有闸没过，别提交。"
fi
exit "$fail"
