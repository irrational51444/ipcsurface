"""量一量手写解析器在真包上的实际覆盖：不是感觉，是数。

三个指标：
1. 未知节点率（kind == 'Other'）——解析器不认识、只能跳过的记号；
2. 结构产量（函数/调用/成员节点数）——认得越多，这些越大；
3. 耗时（MB/秒）——真包上还跑不跑得动。
"""
import os
import sys
import time

ROOT = r'C:\Users\irrational\Desktop\rea-lab'
sys.path.insert(0, ROOT)

import ipcsurface as t  # noqa: E402
import jsast  # noqa: E402

PKGS = [
    ('obsidian', r'C:\Users\irrational\AppData\Local\Programs\Obsidian\resources\obsidian.asar'),
    ('dsh', r'C:\Users\irrational\AppData\Local\Programs\DeepSeek Harness\resources\app.asar'),
    ('douyin', r'C:\Program Files (x86)\ByteDance\douyin\8.8.0\resources\app.asar'),
]


def measure(path, limit=6):
    hdr, files = t.read_asar(path)
    try:
        names = [rel for rel in files.keys() if rel.endswith('.js') and files[rel]]
        names.sort(key=lambda rel: -len(files[rel]))
        targets = names[:limit]
        rows = []
        for rel in targets:
            text = files[rel].decode('utf-8', 'ignore')
            started = time.time()
            program = jsast.parse(text)
            elapsed = time.time() - started
            kinds = {}
            for node in jsast.walk(program):
                kinds[node.kind] = kinds.get(node.kind, 0) + 1
            total = sum(kinds.values())
            unknown = kinds.get('Other', 0)
            rows.append({
                'file': rel,
                'kb': len(text) / 1024.0,
                'seconds': elapsed,
                'nodes': total,
                'unknown': unknown,
                'functions': kinds.get('Function', 0),
                'calls': kinds.get('Call', 0),
                'members': kinds.get('Member', 0),
            })
        return rows
    finally:
        files.close()


def main():
    for label, path in PKGS:
        if not os.path.exists(path):
            print('%s: 本机没有，跳过' % label)
            continue
        rows = measure(path)
        print('=== %s' % label)
        total_kb = sum(r['kb'] for r in rows)
        total_sec = sum(r['seconds'] for r in rows)
        nodes = sum(r['nodes'] for r in rows)
        unknown = sum(r['unknown'] for r in rows)
        print('  最大 %d 个文件：%.0f KB，%.2f 秒（%.1f MB/s）'
              % (len(rows), total_kb, total_sec, (total_kb / 1024.0) / max(total_sec, 1e-6)))
        print('  节点 %d，其中不认识 %d（%.2f%%）' % (nodes, unknown, 100.0 * unknown / max(nodes, 1)))
        print('  函数 %d，调用 %d，成员访问 %d'
              % (sum(r['functions'] for r in rows), sum(r['calls'] for r in rows),
                 sum(r['members'] for r in rows)))
        for row in rows[:3]:
            print('    %-52s %6.0f KB  %5.2fs  未知 %d'
                  % (row['file'][-52:], row['kb'], row['seconds'], row['unknown']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
