"""每个 IPC 通道能碰到哪些危险 API：同文件可达 + 跨文件一跳。

用法：python scripts/channel_sinks.py <路径.asar> [主文件]
只报「能碰到」，不报「可被滥用」——两者不是一回事。
"""
import collections
import sys

sys.path.insert(0, __file__.rsplit('scripts', 1)[0])

import ipcsurface as t
import jsparse
import jssem


def biggest_js(blob_name, files):
    best, size = None, -1
    for rel in files.keys():
        if not rel.endswith('.js'):
            continue
        if files[rel] is None:
            continue
        size_now = len(files[rel])
        if size_now > size:
            best, size = rel, size_now
    return best


def run(asar, main_rel=None):
    header, files = t.read_asar(asar)
    try:
        names = list(files.keys())
        main_rel = main_rel or ('lib/main.js' if 'lib/main.js' in names else biggest_js(None, files))
        text = files[main_rel].decode('utf-8', 'ignore')
    finally:
        files.close()

    tokens = jsparse.tokenize(text)
    defs = jsparse.function_defs(tokens)
    objects = t.parse_object_literals(text)
    regs = [r for r in jsparse.ipc_registrations(tokens, objects) if r['channel']]

    kinds = collections.Counter()
    rows = []
    for reg in regs:
        found = []
        span = reg.get('span')
        if span:
            found += jssem.sinks_in_span(tokens, span[0], span[1])
        for calls in jssem.reachable_sinks(tokens, defs, list(reg['calls'])).values():
            found += calls
        rows.append((reg['channel'], sorted(set(found))))
        for call in found:
            kinds[jssem.danger_kind(call)] += 1

    hit = [r for r in rows if r[1]]
    print(f'{asar}（主文件 {main_rel}）')
    print(f'  通道 {len(rows)}，能碰到危险 API 的 {len(hit)}')
    print(f'  按类别 {dict(sorted(kinds.items()))}')
    for channel, calls in hit[:10]:
        print(f'    {channel}: {calls}')
    return 0


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(run(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None))
