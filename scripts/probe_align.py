"""运行时 vs 静态 的对齐率：探针真跑出来的通道名，静态分析认得几条。

路线图 P1-8 的指标。探针（probe/run.js + scripts/probe_preload.js）在真 Electron
里跑一遍，把运行时注册的通道名吐出来；这里拿它跟静态的 analyse_asar 比：
对齐率 = 运行时名字里静态也认得的 / 运行时名字总数。

- 对齐率低 = 静态漏了（动态注册、名字拼装），是「看不到」；
- 对齐率高但静态多报 = 静态误报。

用法：
    python scripts/probe_align.py probe.json app.asar

probe.json 是 scripts/probe_to_json.py 的产出（含 handlers / listeners）。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ipcsurface as t  # noqa: E402


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    probe_path, asar_path = sys.argv[1], sys.argv[2]

    with open(probe_path, encoding='utf-8') as fh:
        probe = json.load(fh)
    runtime = set(probe.get('handlers', []) + probe.get('listeners', []))

    facts, _n, _b = t.analyse_asar(asar_path)
    static = set(facts['channels'])

    found = runtime & static
    missed = runtime - static
    align = len(found) / len(runtime) if runtime else 0

    print(f'运行时注册 {len(runtime)} 条，静态认得 {len(found)} 条，'
          f'对齐率 {align:.0%}')
    if missed:
        print('静态没认到的：', ', '.join(sorted(missed)[:20]))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
