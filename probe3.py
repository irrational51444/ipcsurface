import json, sys

p = sys.argv[1] if len(sys.argv) > 1 else 'out/evidence'
d = json.load(open(p, encoding='utf-8-sig'))
g = d['records'][0]['normalized_result']['graph']

seen = set()
for e in g['edges']:
    k = e['relation']
    if k in seen:
        continue
    seen.add(k)
    print('===', k)
    print('props:', json.dumps(e.get('properties'), ensure_ascii=False)[:400])
    print('loc:', json.dumps(e['evidence'].get('location', {}).get('value'), ensure_ascii=False)[:160])
    print('conf:', e['evidence'].get('confidence'))

print('\n#### node kinds')
kk = {}
for n in g['nodes']:
    kk[n['kind']] = kk.get(n['kind'], 0) + 1
print(json.dumps(kk, ensure_ascii=False))
print('\n#### node samples')
for n in g['nodes'][:4]:
    print(json.dumps(n, ensure_ascii=False)[:600])
