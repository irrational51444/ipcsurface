import ipcsurface as m
import jsparse

path = r'C:\Users\irrational\AppData\Local\Programs\Obsidian\resources\obsidian.asar'
header, af = m.read_asar(path)
text = af['main.js'].decode('utf-8', 'ignore')
toks = jsparse.tokenize(text)
objects = m.parse_object_literals(text)
regs = jsparse.ipc_registrations(toks, objects)

member_calls = 0
channels_with_member_calls = 0
samples = []
for reg in regs:
    span = reg.get('span')
    if not span or not reg['channel']:
        continue
    hits = []
    for i in range(span[0], min(span[1], len(toks) - 3)):
        if (toks[i].kind == 'ident' and toks[i + 1].text == '.'
                and toks[i + 2].kind == 'ident' and toks[i + 3].text == '('):
            hits.append(toks[i].text + '.' + toks[i + 2].text)
    if hits:
        channels_with_member_calls += 1
        member_calls += len(hits)
        if len(samples) < 8:
            samples.append((reg['channel'], hits[:4]))

print('channels', len([r for r in regs if r['channel']]))
print('channels with member calls inside handler', channels_with_member_calls)
print('member calls total', member_calls)
for s in samples:
    print('  ', s)
