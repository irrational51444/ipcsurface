"""校准：把「能信多少」拆成两层，各自拿人工标准答案验。

路线图 P2-9 第二刀。第一刀发现：strength 档位量的是「通道名可信度」，
却拿去和「危险 API 对错」混在一张表里，于是 0.9 档反而比 1.0 档准——
那不是 bug，是两个不同的问题被塞进一个框里。这一刀把它们拆开：

  表一 名字层：evidence 的 strength 档位，管「通道名是不是真写死/还原/穷举」。
       要校准它，得有人工判过「哪些通道名是假的」。现在 golden 里没有假名样本
       （人工读到的名字都是真的），所以名字层先如实标注「缺假名样本，暂不能校准」，
       附上能算的：名字层召回率（人工确认过的名字，工具报出多少）。

  表二 sink 层：通道名对的前提下，报出来的危险 API 对不对。
       用「sink 路径强度」分档——直连 > 双口径证实 > 同文件链 > 同名多义借来 >
       仅 AST 借来——拿 verified（对）和 false_positive（错）验这条梯度是不是
       真的能分出对错。这是「API 精确率 24%」那件事的结构化拆解。

用法：python scripts/calibration.py
数据：tests/golden/real_packages.json

性能说明：只对「有 verified 或 false_positive 标注」的包做完整扫描（sink 层
有数据才有得校准）。只有 unverified 的包（抖音、bilibili）名字存在性已在 golden
人工确认过、工具报出的事实也写在「依据」里，不再扫一遍 asar——那是白烧几十秒。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ipcsurface as t  # noqa: E402
from jsreport import SINK_TIER_ORDER, sink_tier  # noqa: E402

GOLD = os.path.join(ROOT, 'tests', 'golden', 'real_packages.json')


def _labelled(gold):
    """有 sink 标注的包（verified 或 false_positive 非空）——sink 层校准的数据源。"""
    for name, spec in gold['packages'].items():
        if spec.get('verified') or spec.get('false_positive'):
            yield name, spec


def main():
    gold = json.load(open(GOLD, encoding='utf-8'))

    # 名字层
    confirmed = 0
    tier_dist = {}
    # sink 层
    tiers = {name: [0, 0] for name in SINK_TIER_ORDER}

    for name, spec in _labelled(gold):
        path = spec['asar']
        if not os.path.exists(path):
            continue
        facts, _n, _b = t.analyse_asar(path)
        evidence = t.channel_sources(facts)
        ast = facts.get('channel_sinks_ast') or facts.get('channel_sinks') or {}
        verified = spec.get('verified') or {}
        known_fp = spec.get('false_positive') or {}

        # 表一：名字层（只数人工确认过的真名）
        names = set(verified) | set(known_fp)
        confirmed += len(names)
        for nm in names:
            item = evidence.get(nm) or {}
            tier_dist[item.get('strength', 0.0)] = tier_dist.get(
                item.get('strength', 0.0), 0) + 1

        # 表二：sink 层（对错按 sink 路径强度分档）
        for ch in verified:
            for api in verified[ch]:
                if ch in ast and api in ast[ch]:
                    tiers[sink_tier(facts, ch, api)][0] += 1
        for ch in known_fp:
            for api in known_fp[ch]:
                if ch in ast and api in ast[ch]:
                    tiers[sink_tier(facts, ch, api)][1] += 1

    # 只有 unverified 的包（抖音 22、bilibili 1）：名字已人工确认是真的，
    # 工具报出的事实也写在 golden 的「依据」里，直接计入名字数，不扫 asar。
    unverified_total = 0
    for name, spec in gold['packages'].items():
        if spec.get('verified') or spec.get('false_positive'):
            continue
        unverified_total += len(spec.get('unverified') or [])
    confirmed += unverified_total

    print('== 表一：名字层 ==')
    if not confirmed:
        print('没有能跑的应用，校准没跑成')
        return 2
    print(f'人工确认过的通道名 {confirmed} 条（其中 {unverified_total} 条只确认了'
          f'名字真、sink 读不到，不参与表二）')
    if tier_dist:
        print('| strength 档 | 通道名数 |')
        print('| --- | --- |')
        for tier in sorted(tier_dist, reverse=True):
            print(f'| {tier} | {tier_dist[tier]} |')
    print('名字层暂不能校准，两个原因，都是缺样本：')
    print('  1. 精确率要「假通道名」样本——工具瞎编的名字，golden 里没有；')
    print('  2. 召回率不能拿 golden 算——人工只核「工具报出的」名字，'
          '所以「报出的/确认过的」必然是 100%，这是循环论证，不代表不漏。')
    print('  真正的不漏要拿运行时探针对齐（P1-8 probe_align，实测 71%）。')
    print()

    print('== 表二：sink 层（危险 API 对错） ==')
    print('| sink 路径档 | 对 | 误报 | 精确率 |')
    print('| --- | --- | --- | --- |')
    rows = []
    for tier in SINK_TIER_ORDER:
        tp, fp = tiers[tier]
        prec = tp / (tp + fp) if (tp + fp) else None
        rows.append((tier, tp, fp, prec))
        shown = '—' if prec is None else f'{prec:.0%}'
        print(f'| {tier} | {tp} | {fp} | {shown} |')

    precs = [(tier, tp, fp, prec) for tier, tp, fp, prec in rows if prec is not None]
    if not precs:
        print('sink 层没有能跑的样本，校准没跑成')
        return 2

    bad = []
    for i in range(1, len(precs)):
        higher = precs[i - 1]
        lower = precs[i]
        if lower[3] > higher[3] + 0.10:
            bad.append((lower, higher))
    print()
    if bad:
        for (t_l, _tp, _fp, p_l), (t_h, _tp2, _fp2, p_h) in bad:
            print(f'倒挂：{t_l} 档精确率 {p_l:.0%} 反而高于更高档 {t_h} 的 {p_h:.0%}')
        print('结论：sink 路径强度档和「对不对」没有单调关系，名不副实，要查')
        return 1
    print('sink 层单调成立：路径越可信，精确率越高（倒挂容忍 ≤10%）')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
