"""基准测试：拿人工标注的标准答案，算通道级与 API 级的精确率 / 召回率。

这是路线图 P0-4 的复算入口。数据源是 tests/golden/real_packages.json——
那里每条通道都有人工依据（读了源码、写了为什么对/为什么错）。

口径（写死，别漂）：
- 通道级：一个通道「说对了」= 工具报了它、且它名下至少一条可达危险 API 对得上。
  精确率 = 说对的通道数 / 工具报出的通道数（扣掉已知误报）
  召回率 = 说对的通道数 / 人工核对过的通道数
- API 级：在人工核对的通道上，按「该通道该有的危险 API」逐个对。
  精确率 = 报对的 API 数 / 报出的 API 数
  召回率 = 报对的 API 数 / 该有的 API 数

包不在本机就跳过，跳过不是 0 分，是「没测」。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ipcsurface as t  # noqa: E402

GOLD = os.path.join(ROOT, 'tests', 'golden', 'real_packages.json')


def main():
    gold = json.load(open(GOLD, encoding='utf-8'))
    rows = []
    agg = {'tp_ch': 0, 'reported_ch': 0, 'verified_ch': 0,
           'tp_api': 0, 'reported_api': 0, 'expected_api': 0}
    for name, spec in gold['packages'].items():
        verified = spec['verified']
        path = spec['asar']
        if not verified:
            # 没有人工标注就等于没测。以前这里会打出一行 0%，
            # 读的人分不清「工具一条没报」和「我还没核」——那不是数字，是噪音。
            print(f'{name}: 还没有人工标注，跳过（没测，不是 0 分）')
            continue
        if not os.path.exists(path):
            print(f'{name}: 本机没有这个包，跳过')
            continue
        facts, _n, _b = t.analyse_asar(path)
        # 两路口径要合并，不是二选一。以前写的是 `ast or 名字级`：
        # ast 那层只要有一条非空，名字级那批就整个被丢掉，
        # 抖音 / bilibili / vivo / ACLOS 四个包因此算出来全是 0——
        # 那不是「工具没报」，是尺子把它们扔了。
        got = {}
        for source in (facts.get('channel_sinks'),
                       facts.get('channel_sinks_ast')):
            for key, apis in (source or {}).items():
                if apis:
                    got.setdefault(key, set()).update(apis)

        verified = spec['verified']
        known_miss = spec.get('known_miss') or {}
        known_fp = set(spec.get('false_positive') or {})

        # 通道级
        correct_ch = [c for c, apis in verified.items()
                      if c in got and (got[c] & set(apis))]
        reported_ch = [c for c in got if c not in known_fp]
        tp_ch = len(correct_ch)
        verified_ch = len(verified)

        # API 级
        tp_api = fp_api = fn_api = 0
        for c, apis in verified.items():
            have = got.get(c, set())
            tp_api += len(have & set(apis))
            fn_api += len(set(apis) - have - set(known_miss.get(c) or []))
            fp_api += len(have - set(apis) - set(known_miss.get(c) or []))
        reported_api = tp_api + fp_api
        expected_api = tp_api + fn_api

        agg['tp_ch'] += tp_ch
        agg['reported_ch'] += len(reported_ch)
        agg['verified_ch'] += verified_ch
        agg['tp_api'] += tp_api
        agg['reported_api'] += reported_api
        agg['expected_api'] += expected_api

        rows.append((name, tp_ch, len(reported_ch), verified_ch,
                     tp_api, reported_api, expected_api))

    print()
    print('| 应用 | 通道 P | 通道 R | 已核通道 | API P | API R |')
    print('| --- | --- | --- | --- | --- | --- |')
    for name, tp_ch, rep_ch, ver_ch, tp_api, rep_api, exp_api in rows:
        p_ch = tp_ch / rep_ch if rep_ch else 0
        r_ch = tp_ch / ver_ch if ver_ch else 0
        p_api = tp_api / rep_api if rep_api else 0
        r_api = tp_api / exp_api if exp_api else 0
        print(f'| {name} | {p_ch:.0%} | {r_ch:.0%} | {ver_ch} | '
              f'{p_api:.0%} | {r_api:.0%} |')

    if not rows:
        print('没有能跑的应用，标准答案没跑成——这是没测，不是 100%')
        return 2

    p_ch = agg['tp_ch'] / agg['reported_ch'] if agg['reported_ch'] else 0
    r_ch = agg['tp_ch'] / agg['verified_ch'] if agg['verified_ch'] else 0
    p_api = agg['tp_api'] / agg['reported_api'] if agg['reported_api'] else 0
    r_api = agg['tp_api'] / agg['expected_api'] if agg['expected_api'] else 0
    print(f'| 合计 | {p_ch:.0%} | {r_ch:.0%} | {agg["verified_ch"]} | '
          f'{p_api:.0%} | {r_api:.0%} |')
    print()
    print(f'通道级：精确率 {p_ch:.1%}、召回率 {r_ch:.1%}'
          f'（{agg["tp_ch"]}/{agg["reported_ch"]} 报对，'
          f'{agg["tp_ch"]}/{agg["verified_ch"]} 召回）')
    print(f'API 级：精确率 {p_api:.1%}、召回率 {r_api:.1%}'
          f'（{agg["tp_api"]}/{agg["reported_api"]} 报对，'
          f'{agg["tp_api"]}/{agg["expected_api"]} 召回）')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
