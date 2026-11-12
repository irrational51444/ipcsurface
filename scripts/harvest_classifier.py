"""候选分类器：把「像通道名」和「像噪音」分开，并且说清凭什么。

路线图新四项之一。`harvested` 里的候选是一堆「长得像通道的字符串」，以前只按
机械事实分四档（channel / near-ipc / clustered / stray）。这里再往前一步：给出
0~1 的可解释得分 + 理由，让读的人知道为什么它被排在前面。

不训练黑盒模型（零依赖、也不该把判断藏进权重里）。权重是先验，用 golden 数据
校准准确率——脚本只报准确率和误判样本，不自己改权重。

用法：
    python scripts/harvest_classifier.py            # 用 tests/golden/real_packages.json 的真包
    python scripts/harvest_classifier.py <asar>     # 只跑一个包
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ipcsurface as t  # noqa: E402
import jslabels  # noqa: E402

GOLD = os.path.join(ROOT, 'tests', 'golden', 'real_packages.json')
THRESHOLD = 0.5


def evaluate(asar_path, known_channels):
    """返回 (正样本得分列表, 负样本得分列表, 明细)。"""
    facts, _n, _b = t.analyse_asar(asar_path)
    harvested = facts.get('harvested') or {}
    grades = facts.get('harvest_grades') or {}
    positives, negatives, detail = [], [], []
    for name in harvested:
        grade = grades.get(name)
        score, reasons = jslabels.harvest_confidence(name, grade)
        is_positive = name in known_channels or grade == 'channel'
        (positives if is_positive else negatives).append(score)
        detail.append({'name': name, 'grade': grade, 'score': round(score, 2),
                       'reasons': reasons, 'positive': is_positive})
    return positives, negatives, detail


def main():
    if len(sys.argv) == 2:
        path = sys.argv[1]
        gold = {'packages': {'arg': {'asar': path, 'verified': {}}}}
    else:
        gold = json.load(open(GOLD, encoding='utf-8'))

    all_pos, all_neg = [], []
    per_pkg = []
    for name, spec in gold['packages'].items():
        path = spec['asar']
        if not os.path.exists(path):
            continue
        known = set(spec.get('verified') or {})
        pos, neg, _detail = evaluate(path, known)
        all_pos.extend(pos)
        all_neg.extend(neg)
        per_pkg.append((name, len(pos), len(neg),
                        sum(pos) / len(pos) if pos else None,
                        sum(neg) / len(neg) if neg else None))
        print(f'{name}: 正样本 {len(pos)} 条，负样本 {len(neg)} 条', file=sys.stderr)

    if not all_pos and not all_neg:
        print('没有能跑的包，分类器没跑成')
        return 2

    def rate(values, want_positive):
        """判对率：正样本要 ≥ 阈值，负样本要 < 阈值。"""
        if not values:
            return None
        if want_positive:
            hit = sum(1 for v in values if v >= THRESHOLD)
        else:
            hit = sum(1 for v in values if v < THRESHOLD)
        return hit / len(values)

    print('| 包 | 正样本 | 负样本 | 正样本均分 | 负样本均分 |')
    print('| --- | --- | --- | --- | --- |')
    for name, np_, nn, avg_p, avg_n in per_pkg:
        print(f'| {name} | {np_} | {nn} | '
              f'{avg_p if avg_p is None else f"{avg_p:.2f}"} | '
              f'{avg_n if avg_n is None else f"{avg_n:.2f}"} |')
    print()
    r_pos = rate(all_pos, True)
    r_neg = rate(all_neg, False)
    print(f'阈值 {THRESHOLD}：正样本判对 {r_pos}，负样本判对 {r_neg}')
    print('正样本应尽量高、负样本应尽量低；两个都高说明阈值没用，两个都低说明特征不对')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
