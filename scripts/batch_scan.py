"""批量扫描：把一个目录（或一串 .asar 路径）全部跑一遍，出汇总表。

用法：
    python scripts/batch_scan.py <目录或路径...> [--json out.json] [--md out.md]

对每个包跑静态 analyse_asar，汇总：
- 通道数 / 能碰危险 API 的通道数
- 能力标签分布（fs / child_process / shell / path / network / eval）
- 候选数、强混淆数

跑不动的包（加壳/损坏）单独跳过并出声，不混进结果里当 0。
"""
import argparse
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ipcsurface as t  # noqa: E402
import jslabels  # noqa: E402


def collect(paths):
    """目录递归找 .asar；也接受直接给的 .asar 路径。"""
    out = []
    for p in paths:
        if os.path.isdir(p):
            out.extend(sorted(glob.glob(os.path.join(p, '**', '*.asar'), recursive=True)))
        elif p.lower().endswith('.asar'):
            out.append(p)
    seen = set()
    unique = []
    for p in out:
        real = os.path.realpath(p)
        if real not in seen:
            seen.add(real)
            unique.append(p)
    return unique


def scan_one(path):
    facts, count, total = t.analyse_asar(path)
    sinks = facts.get('channel_sinks_ast') or facts.get('channel_sinks') or {}
    hit = {k: v for k, v in sinks.items() if v}
    labels = {}
    for ch, apis in hit.items():
        for label in jslabels.risk_labels(apis):
            labels[label] = labels.get(label, 0) + 1
    return {
        'path': path,
        'files': count,
        'bytes': total,
        'channels': len(facts['channels']),
        'danger_channels': len(hit),
        'risk_labels': labels,
        'harvested': len(facts.get('harvested') or {}),
        'strong_obfuscation': sum(1 for _n, _w, lvl in (facts.get('obfuscation') or [])
                                  if lvl == 'strong'),
    }


def label_of(path):
    """给表格里一行起个短名字：用文件名去后缀；名字太通用（app/index）就往上找一级。"""
    base = os.path.basename(path)
    stem = base[:-5] if base.lower().endswith('.asar') else base
    if stem not in ('app', 'index', 'main', 'electron', 'resources'):
        return stem
    real = os.path.realpath(path)
    parent = os.path.dirname(os.path.dirname(real))
    return os.path.basename(parent) + '/' + stem


def to_md(rows):
    lines = ['| 包 | 文件数 | 通道 | 碰危险API | 能力标签 | 候选 | 强混淆 |',
             '| --- | --- | --- | --- | --- | --- | --- |']
    for r in rows:
        labels = '、'.join(f'{k}×{v}' for k, v in sorted(r['risk_labels'].items())) or '—'
        lines.append(f"| {label_of(r['path'])} | {r['files']} | {r['channels']} "
                     f"| {r['danger_channels']} | {labels} | {r['harvested']} "
                     f"| {r['strong_obfuscation']} |")
    return '\n'.join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('paths', nargs='+', help='目录或 .asar 路径')
    ap.add_argument('--json', help='把汇总写进这个 json')
    ap.add_argument('--md', help='把表格写进这个 md')
    args = ap.parse_args()

    targets = collect(args.paths)
    if not targets:
        print('没找到 .asar（给目录或直接给 .asar 路径）')
        return 2

    rows, skipped = [], []
    for p in targets:
        print(f'扫 {p} ...', file=sys.stderr)
        try:
            rows.append(scan_one(p))
        except SystemExit as exc:
            print(f'  跳过：{exc}', file=sys.stderr)
            skipped.append((p, str(exc)))
        except Exception as exc:  # noqa: BLE001 —— 单个包崩了不能带走整批
            print(f'  出错：{type(exc).__name__}: {exc}', file=sys.stderr)
            skipped.append((p, f'{type(exc).__name__}: {exc}'))

    text = to_md(rows) if rows else '（没有扫成的包）'
    print(text)
    if skipped:
        print(f'\n跳过的 {len(skipped)} 个（这些是「没扫」，不是「没问题」）：')
        for p, why in skipped:
            print(f'  - {p}：{why}')

    if args.md:
        with open(args.md, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(text + '\n')
        print(f'\n表格写进 {args.md}', file=sys.stderr)
    if args.json:
        with open(args.json, 'w', encoding='utf-8', newline='\n') as fh:
            json.dump({'rows': rows, 'skipped': [{'path': p, 'why': w} for p, w in skipped]},
                      fh, ensure_ascii=False, indent=2)
        print(f'汇总写进 {args.json}', file=sys.stderr)
    return 0 if rows else 1


if __name__ == '__main__':
    raise SystemExit(main())
