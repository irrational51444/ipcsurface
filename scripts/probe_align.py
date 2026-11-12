"""运行时 vs 静态 的对齐率：探针真跑出来的通道名，静态分析认得几条。

路线图 P1-8 的指标。探针（probe/run.js + scripts/probe_preload.js）在真 Electron
里跑一遍，把运行时注册的通道名吐出来；这里拿它跟静态的 analyse_asar 比：
对齐率 = 运行时名字里静态也认得的 / 运行时名字总数。

- 对齐率低 = 静态漏了（动态注册、名字拼装），是「看不到」；
- 对齐率高但静态多报 = 静态误报。

用法：
    python scripts/probe_align.py probe.json app.asar [--min-align 0.7]

probe.json 是 scripts/probe_to_json.py 的产出（含 handlers / listeners）。
--min-align 给一个 0~1 的门禁：对齐率低于它退 1（挂 CI 用）。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ipcsurface as t  # noqa: E402

# 平台/进程内置的「通道」，不是应用代码注册的，静态本就不该有。对齐率要分
# 两个口径：总对齐（含内置，会被内置拉低）和应用通道对齐（排除内置，看静态
# 到底漏没漏应用自己的通道）。
BUILTIN_PREFIXES = ('IMPORT_SHARED_TEXTURE',)
BUILTIN_EXACT = ('error', 'uncaughtException')


def main():
    if len(sys.argv) not in (3, 4, 5):
        print(__doc__)
        return 2
    probe_path, asar_path = sys.argv[1], sys.argv[2]
    min_align = 0.0
    if '--min-align' in sys.argv:
        try:
            min_align = float(sys.argv[sys.argv.index('--min-align') + 1])
        except (ValueError, IndexError):
            print('--min-align 后面要跟一个 0~1 的数')
            return 2

    with open(probe_path, encoding='utf-8-sig') as fh:
        probe = json.load(fh)
    runtime = set(probe.get('handlers', []) + probe.get('listeners', []))

    facts, _n, _b = t.analyse_asar(asar_path)
    static = set(facts['channels'])

    def builtin(name):
        return name in BUILTIN_EXACT or name.startswith(BUILTIN_PREFIXES)

    app_runtime = {n for n in runtime if not builtin(n)}
    found = runtime & static
    app_found = app_runtime & static
    align = len(found) / len(runtime) if runtime else 0
    app_align = len(app_found) / len(app_runtime) if app_runtime else 0

    print(f'运行时注册 {len(runtime)} 条，静态认得 {len(found)} 条，'
          f'对齐率 {align:.0%}')
    print(f'应用通道 {len(app_runtime)} 条，静态认得 {len(app_found)} 条，'
          f'对齐率 {app_align:.0%}')

    # 分层：动态不是替代静态，是印证。三层一起看才知道差在哪。
    layers = t.crosscheck_layers(runtime, static)
    print()
    print(f"  双向印证 {len(layers['both'])} 条（静态认得，运行时也注册）")
    print(f"  仅静态   {len(layers['static_only'])} 条（静态认得，这次没跑起来）")
    print(f"  仅动态   {len(layers['runtime_only'])} 条（运行时注册，静态没认出）")
    if layers['runtime_only']:
        print('  仅动态是静态的漏：', ', '.join(layers['runtime_only'][:20]))
    if layers['static_only']:
        print('  仅静态不是错（懒加载/条件分支没走到）：',
              ', '.join(layers['static_only'][:10]))

    if min_align and align < min_align:
        print(f'对齐率 {align:.0%} 低于门禁 {min_align:.0%}，静态漏了应用通道')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
