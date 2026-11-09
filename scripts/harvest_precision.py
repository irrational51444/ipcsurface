"""在有人工标注的靶场上，算「打捞出来的候选」的真实误报率。

为什么要这个：报告里那句「221 个候选」只有数量，没有准不准。
数量大看着像收获，其实可能是噪音。这里用我逐份源码数出来的通道清单
当答案纸，把候选分成「确实是通道名」和「不是」，算一个真数字。

**它只说明这几份靶场。** 真实应用那 221 个候选没有人工核对过，
所以那边的准确率仍然是未知——未知就写未知，不拿靶场的数字顶上去。
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import ipcsurface as t  # noqa: E402

GOLDEN = os.path.join(ROOT, 'tests', 'golden', 'ground_truth.json')


def targets():
    with open(GOLDEN, encoding='utf-8') as fh:
        truth = json.load(fh)
    for name, spec in sorted(truth['fixtures'].items()):
        path = os.path.join(ROOT, 'examples', 'build', name)
        if os.path.exists(path) and spec.get('channels') is not None:
            yield name, path, set(spec['channels'])


IPC_TOKENS = (b'ipcMain', b'ipcRenderer', b'contextBridge')


def candidate_contexts(path, names):
    """给每个候选名找它的出现现场：在哪个文件、多少行、附近有没有 IPC 调用。

    只翻提到 IPC 的文件——真实应用 22,102 个文件里只有 6 个提到，
    所以这一步不贵。旁边 60 字符内出现 ipcMain / ipcRenderer / contextBridge，
    说明这个名字是长在调用旁边的，比满包乱蹦的字符串更像真名字。
    """
    header, files = t.read_asar(path)
    found = {}
    try:
        for rel in files.keys():
            if not rel.endswith(t.TEXT_EXT):
                continue
            blob = files[rel]
            if not any(token in blob for token in IPC_TOKENS):
                continue
            text = blob.decode('utf-8', 'ignore')
            for name in names:
                start = text.find(name)
                if start == -1:
                    continue
                near = False
                window = text[max(0, start - 60):start + len(name) + 60]
                if any(token.decode() in window for token in IPC_TOKENS):
                    near = True
                found.setdefault(name, []).append(
                    (f'{rel}:{t.line_of(text, start)}', near))
    finally:
        if files is not None:
            files.close()
    return found


def real_app_composition():
    """真实应用上，候选的构成（不是准确率）。

    没有人工核对过的名字，就不能说它错——所以这里只算能机械算的两件事：
    多少个候选同时也是静态看见的名字（那就不算误报），多少个是孤零零的候选。
    剩下的准确率仍然是未知，未知就写未知。
    """
    candidates = [os.path.join(ROOT, 'build', 'mut', 'app.asar'),
                  os.path.join(ROOT, 'build', 'realapp2', 'app.asar')]
    path = next((item for item in candidates if os.path.exists(item)), None)
    if path is None:
        return None
    facts, _count, _total = t.analyse_asar(path)
    harvested = set(facts.get('harvested') or {})
    seen_static = {name for name, _w in facts['handlers'] + facts['invokes']}
    overlap = harvested & seen_static
    return {
        'path': os.path.relpath(path, ROOT),
        'channels': len(facts['channels']),
        'harvested': len(harvested),
        'also_static': len(overlap),
        'alone': len(harvested - seen_static),
        'alone_names': sorted(harvested - seen_static),
    }


def main():
    rows = []
    for name, path, truth_names in targets():
        facts, _count, _total = t.analyse_asar(path)
        harvested = set(facts.get('harvested') or {})
        if not harvested:
            rows.append((name, 0, 0, None))
            continue
        hit = sorted(harvested & truth_names)
        rows.append((name, len(harvested), len(hit), len(hit) / len(harvested)))

    print('靶场            候选数   其中是真通道名   准确率')
    scored = [row for row in rows if row[3] is not None]
    for name, total, hit, rate in rows:
        shown = '—' if rate is None else f'{rate:.2f}'
        print(f'{name:18}{total:>5}{hit:>12}      {shown}')
    if not scored:
        print('没有可算的靶场：先跑 examples/build.sh')
        return 1
    total = sum(row[1] for row in scored)
    hit = sum(row[2] for row in scored)
    print(f'\n合计：{total} 个候选，{hit} 个是真通道名，准确率 {hit / total:.2f}')
    print('注：这只说明这几份靶场（写法都是我自己写的，样本很小）。')

    real = real_app_composition()
    print()
    if real:
        print(f"真实应用（{real['path']}）：{real['channels']} 条通道，{real['harvested']} 个候选")
        print(f"  其中 {real['also_static']} 个同时也是静态看见的通道名——那些不是误报，是同一件事的两条路")
        print(f"  剩下 {real['alone']} 个是孤证候选，**没有人工核对过，准确率未知**")
        print('  没有数字不是漏算，是没核过；编一个数比留空更坏。')

        # 再往下走一步：这些孤证候选长在哪儿？
        facts_path = real['path']
        alone = real['alone_names']
        if True:
            contexts = candidate_contexts(facts_path, alone)
            near = [name for name in alone
                    if any(flag for _where, flag in contexts.get(name, []))]
            nowhere = [name for name in alone if name not in contexts]
            print(f'  在提到 IPC 的文件里找得到出处的：{len(contexts)} 个，其中 {len(near)} 个就在调用旁边（60 字符内）')
            print(f'  只在别的文件里出现、离 IPC 很远的：{len(nowhere)} 个')

            # 名字是长在「表」里的，不长在调用旁边：同前缀一簇的候选越多，越像一张通道表
            from collections import Counter

            def prefix_of(name):
                return name.split(':', 1)[0] if ':' in name else ''

            counts = Counter(prefix_of(name) for name in alone)
            clustered = [name for name in alone if counts[prefix_of(name)] >= 3]
            print(f'  同前缀 ≥3 个、成簇出现的：{len(clustered)} 个；零星散着的：{len(alone) - len(clustered)} 个')
            print('  最大的几个前缀：' + '、'.join(
                f'{name}={count}' for name, count in counts.most_common(5)))
            sample = sorted(contexts.items())[:20]
            print('\n  抽 20 个给你自己核（名字 @ 位置，★ = 就在 IPC 调用旁边）：')
            for name, places in sample:
                where, flag = places[0]
                print(f"    {'★' if flag else ' '} {name[:44]:<46}{where}")
        pass
    else:
        print('真实应用不在本机，这一层跳过（不拿靶场的数字顶上去）')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
