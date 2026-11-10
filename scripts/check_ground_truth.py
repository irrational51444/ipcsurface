"""拿人工确认过的标准答案，给真包上的结果打分。

只对 tests/golden/real_packages.json 里 verified 的通道算分：
命中 / 漏报 / 多报。unverified 的通道不算分（没读完就不算数），
包不在本机的直接跳过——这不是「通过」，是「没测」。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ipcsurface as t  # noqa: E402

GOLD = os.path.join(ROOT, 'tests', 'golden', 'real_packages.json')


def main():
    with open(GOLD, encoding='utf-8') as fh:
        gold = json.load(fh)
    total_hit = total_miss = total_extra = total_skip = 0
    for name, spec in gold['packages'].items():
        path = spec['asar']
        if not os.path.exists(path):
            total_skip += 1
            print(f'{name}: 本机没有这个包，跳过（不算通过）')
            continue
        facts, _n, _b = t.analyse_asar(path)
        # 用语法树口径打分：它才是现在的主口径（members/alias/callback 都连得上）。
        # 名字级粗扫只在树没跑出来时兜底。
        sinks = facts.get('channel_sinks_ast') or facts.get('channel_sinks')
        if sinks is None:
            total_skip += 1
            print(f'{name}: 汇点分析没跑出来（channel_sinks 是 null），这次不算')
            continue
        got = {k: set(v) for k, v in sinks.items() if v}
        for channel, apis in spec['verified'].items():
            have = got.get(channel, set())
            hit = have & set(apis)
            allowed_miss = set((spec.get('known_miss') or {}).get(channel) or [])
            miss = set(apis) - have - allowed_miss
            if hit:
                total_hit += 1
            if miss:
                total_miss += 1
                print(f'  漏：{name} / {channel} 少了 {sorted(miss)}（有 {sorted(have)}）')
        # 多报：verified 通道之外，工具报了但人没确认的
        known_fp = spec.get('false_positive') or {}
        extra = [c for c in got if c not in spec['verified'] and c not in known_fp]
        keep = [c for c in extra if c not in spec['unverified']]
        if keep:
            total_extra += len(keep)
            print(f'  多：{name} 报了但没人工确认：{sorted(keep)}')
        print(f'{name}: 已核对 {len(spec["verified"])} 条，'
              f'工具报出 {len(got)} 条（其中 {len(spec["unverified"])} 条还没人读）')
    print(f'\n合计：命中 {total_hit}，漏报 {total_miss}，没人确认却被报 {total_extra}')
    if total_skip:
        # 一个包都没在本机跑成，这个 0 漏报什么都证明不了——按「没查清」退出，
        # 别让 CI 把它读成通过。
        print(f'有 {total_skip} 个包不在本机，标准答案没跑成：这不是通过，是没测')
        return 2
    if total_hit == 0:
        print('一条都没核对上：标准答案或工具至少有一边是空的，先别当通过')
        return 2
    return 0 if total_miss == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
