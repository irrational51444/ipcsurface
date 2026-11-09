"""用人工标注的 ground truth 算召回和精确率。

这是唯一能把「我觉得可信」变成数字的地方：工具说有 N 条，人标了 M 条，
多出来的算误报，少掉的算漏报。数字难看也算数。
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, 'examples', 'build')
TRUTH = os.path.join(ROOT, 'tests', 'golden', 'ground_truth.json')


def main():
    truth = json.load(open(TRUTH, encoding='utf-8'))['fixtures']
    rows = []
    problems = []

    for name, spec in sorted(truth.items()):
        sample = os.path.join(BUILD, name)
        if not os.path.exists(sample):
            print(f'  SKIP {name}（没有这个靶子）')
            continue
        out = os.path.join(BUILD, f'gt-{name}.json')
        proc = subprocess.run([sys.executable, os.path.join(ROOT, 'ipcsurface.py'),
                               sample, '--format', 'json', '-o', out],
                              capture_output=True, text=True, encoding='utf-8',
                              errors='replace')
        if proc.returncode not in (0, 2):
            problems.append(f'{name} 跑不动：{proc.stderr[:80]}')
            continue
        got = set(json.load(open(out, encoding='utf-8'))['channels'])
        want = set(spec['channels'])
        unreachable = set(spec.get('known_unreachable') or [])
        reachable = want - unreachable

        hit = got & want
        extra = got - want
        missed = reachable - got          # 只把「该扫到的」算漏报
        precision = len(hit) / len(got) if got else (1.0 if not want else 0.0)
        recall = len(hit & reachable) / len(reachable) if reachable else 1.0
        coverage = len(hit) / len(want) if want else 1.0

        print(f'  {name}: 对 {len(hit)}/{len(want)} 条'
              f'（precision {precision:.2f} / recall {recall:.2f} / 总覆盖 {coverage:.2f}）')
        if unreachable:
            print(f'    静态扫不到的（已知）：{", ".join(sorted(unreachable))}')
        if missed:
            print(f'    漏报：{", ".join(sorted(missed))}')
        if extra:
            print(f'    误报：{", ".join(sorted(extra))}')
        rows.append({'fixture': name, 'precision': precision, 'recall': recall,
                     'coverage': coverage, 'missed': sorted(missed),
                     'extra': sorted(extra)})

    if problems:
        print()
        for line in problems:
            print('  FAIL ' + line)
        return 1

    if not rows:
        print('没有可比对的靶子')
        return 1

    worst = min(rows, key=lambda r: (r['recall'], r['precision']))
    print()
    print(f'最差的一格：{worst["fixture"]}  recall {worst["recall"]:.2f} / '
          f'precision {worst["precision"]:.2f}')
    total_hit = sum(r['precision'] * 1 for r in rows)
    avg_cov = sum(r['coverage'] for r in rows) / len(rows)
    unreachable = sum(len(spec.get('known_unreachable') or ())
                      for spec in truth.get('fixtures', {}).values())
    if unreachable:
        print(f'平均总覆盖率：{avg_cov:.2f}（含 {unreachable} 个已知扫不到的名字，'
              '所以这个数是真实水平，不是修饰过的）')
    else:
        print(f'平均总覆盖率：{avg_cov:.2f}（没有登记「已知扫不到」的名字；'
              '这个数只说明这几个靶场，不代表真实应用）')

    # 底线：能扫到的那些必须扫到（recall），标出来的必须基本对（precision）
    bad = [r for r in rows if r['recall'] < 0.8]
    if bad:
        print('  FAIL 下面这些 recall 低于 0.8：' + '、'.join(r['fixture'] for r in bad))
        return 1
    dirty = [r for r in rows if r['extra']]
    if dirty:
        print('  注意 这些靶场有误报（不阻断，但每次都会打出来）：'
              + '、'.join(r['fixture'] for r in dirty))

    print('ground truth 比对通过')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
