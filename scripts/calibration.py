"""校准：证据强度档位是不是真的和「对不对」成正比。

路线图 P2-9。strength 档位是这套工具的核心主张——「literal=1.0 比 harvested=0.2 可信」。
这句话不能只靠嘴说，得拿人工核对的标准答案来验：把已核通道按 strength 分档，
看每一档的精确率（对的 / (对的 + 误报的)）是不是随档位单调上升。

用法：python scripts/calibration.py
数据：tests/golden/real_packages.json 里 verified（对）和 false_positive（错）。
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
    # tier -> [TP, FP]
    tiers = {}
    for name, spec in gold['packages'].items():
        path = spec['asar']
        if not os.path.exists(path):
            continue
        facts, _n, _b = t.analyse_asar(path)
        evidence = t.channel_sources(facts)
        verified = spec.get('verified') or {}
        known_fp = spec.get('false_positive') or {}

        for ch in verified:
            item = evidence.get(ch) or {}
            tier = item.get('strength', 0.0)
            buckets = tiers.setdefault(tier, [0, 0])
            buckets[0] += 1
        for ch in known_fp:
            item = evidence.get(ch) or {}
            tier = item.get('strength', 0.0)
            buckets = tiers.setdefault(tier, [0, 0])
            buckets[1] += 1

    if not tiers:
        print('没有能跑的应用，校准没跑成')
        return 2

    print('| strength 档 | 对 | 误报 | 精确率 |')
    print('| --- | --- | --- | --- |')
    rows = []
    for tier in sorted(tiers, reverse=True):
        tp, fp = tiers[tier]
        prec = tp / (tp + fp) if (tp + fp) else 0
        rows.append((tier, tp, fp, prec))
        print(f'| {tier} | {tp} | {fp} | {prec:.0%} |')

    # 单调性检查：档位越高，精确率不该更低（允许倒挂 5 个百分点以内的噪声）。
    # 行已经按 tier 从高到低排好。
    precs = [prec for _t, _tp, _fp, prec in rows]
    bad = []
    for i in range(1, len(precs)):
        if precs[i] > precs[i - 1] + 0.05:
            bad.append((rows[i][0], rows[i - 1][0], precs[i], precs[i - 1]))
    print()
    if bad:
        for higher, lower, ph, pl in bad:
            print(f'倒挂：档位 {higher} 精确率 {ph:.0%} 反而高于更高的档位 {lower} 的 {pl:.0%}')
        print('结论：某档的 strength 和「对不对」没有单调关系，名不副实，要查')
        return 1
    print('档位与精确率单调（高可信档精确率 ≥ 低可信档，倒挂 ≤5% 容忍）')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
