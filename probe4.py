import json, sys

p = sys.argv[1] if len(sys.argv) > 1 else 'out/evidence'
want = {'browser-window', 'context-bridge-api', 'ipc-channel', 'ipc-handler'}
d = json.load(open(p, encoding='utf-8-sig'))
g = d['records'][0]['normalized_result']['graph']
shown = set()
for n in g['nodes']:
    if n['kind'] in want and n['kind'] not in shown:
        shown.add(n['kind'])
        print('#####', n['kind'])
        print(json.dumps(n, ensure_ascii=False, indent=1)[:3000])
        print()
