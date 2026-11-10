"""复核队列：把「要人看一眼」的通道排出来，按该先看的顺序。

排序不是玄学，就三条：
  1. 污点命中（外部输入能到危险参数）—— 这是要动的
  2. 一跳直达（处理函数自己就调了危险 API）—— 一眼能确认
  3. 其它可达（经公共函数）—— 看链路，多半是配置存盘

用法：python scripts/review_queue.py <asar> [--top 10]
"""
import argparse
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ipcsurface as t  # noqa: E402


def build_queue(facts, top):
    sinks = facts.get('channel_sinks') or {}
    paths = facts.get('channel_sink_paths') or {}
    tainted = facts.get('channel_tainted') or {}
    rows = []
    for channel, apis in sinks.items():
        if not apis:
            continue
        chain = paths.get(channel) or {}
        hops = min([item.get('hops', 9) for item in chain.values()] or [9])
        via = next((item.get('via', '') for item in chain.values()), '')
        tier = 3
        if channel in tainted:
            tier = 1
        elif hops <= 1:
            tier = 2
        rows.append({
            'channel': channel,
            'apis': apis,
            'hops': hops,
            'via': via,
            'tier': tier,
            'tainted': bool(channel in tainted),
        })
    rows.sort(key=lambda r: (r['tier'], r['hops'], r['channel']))
    return rows[:top]


def group_by_chain(rows):
    """按「来路」归堆：复核的代价是「有多少条不同的链路」，不是「多少条通道」。

    实测 Obsidian：19 条通道里大半都是 _→ae（存配置）这一条链路带来的。
    把它当成一件事核一次就行，不用一条条看。
    """
    groups = {}
    for row in rows:
        key = row['via'] or '（处理函数自己调的）'
        bucket = groups.setdefault(key, {'apis': set(), 'channels': [], 'tainted': False})
        bucket['apis'].update(row['apis'])
        bucket['channels'].append(row['channel'])
        bucket['tainted'] = bucket['tainted'] or row['tainted']
    return groups


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('asar')
    ap.add_argument('--top', type=int, default=10)
    args = ap.parse_args()
    facts, files, total = t.analyse_asar(args.asar)
    rows = build_queue(facts, args.top)
    print('包：%s（%d 个文件）' % (args.asar, files))
    print('要看的排前 %d 条：\n' % len(rows))
    for row in rows:
        mark = '污点' if row['tainted'] else ('一跳' if row['hops'] <= 1 else '间接')
        print('%-28s %-4s %s' % (row['channel'], mark, ','.join(row['apis'])))
        if row['via']:
            print('    链路：%s' % row['via'])
    if not rows:
        print('（空：没有一条能碰到危险 API）')
        return 0
    groups = group_by_chain(rows)
    print('\n按来路归堆：%d 条通道只对应 %d 条不同链路——核 %d 次就够'
          % (len(rows), len(groups), len(groups)))
    for chain, bucket in sorted(groups.items(), key=lambda kv: -len(kv[1]['channels'])):
        tag = '污点' if bucket['tainted'] else '可达'
        print('  %-22s %s  %d 条通道：%s'
              % (chain, tag, len(bucket['channels']), ','.join(sorted(bucket['apis']))))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
