import json, sys, collections

p = sys.argv[1] if len(sys.argv) > 1 else 'out/evidence'
d = json.load(open(p, encoding='utf-8-sig'))


def walk(o, path=''):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from walk(v, f'{path}.{k}' if path else k)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from walk(v, f'{path}[{i}]')
    else:
        yield path, o


amap = collections.defaultdict(set)
for path, val in walk(d):
    if isinstance(val, str) and 'ledger' in val:
        amap[path].add(val)

print('total paths hitting "ledger":', len(amap))
for path in list(amap)[:40]:
    print(path, '->', list(amap[path])[:3])
