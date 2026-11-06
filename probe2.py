import json, sys

p = sys.argv[1] if len(sys.argv) > 1 else 'out/evidence'
d = json.load(open(p, encoding='utf-8-sig'))
g = d['records'][0]['normalized_result']['graph']
print('graph keys:', list(g.keys()))
print('edge count:', len(g['edges']))
kinds = {}
for e in g['edges']:
    kinds[e.get('type') or e.get('kind') or e.get('relation')] = kinds.get(e.get('type') or e.get('kind') or e.get('relation'), 0) + 1
print('edge kinds:', json.dumps(kinds, ensure_ascii=False, indent=1))
for e in g['edges'][:3]:
    print(json.dumps(e, ensure_ascii=False, indent=1)[:1200])
print('node sample:')
for n in g.get('nodes', [])[:2]:
    print(json.dumps(n, ensure_ascii=False, indent=1)[:800])
