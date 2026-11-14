import ipcsurface as m
import precise_engine as p

PATH = r'C:\Program Files (x86)\ACLOS\Launcher\resources\app.asar'
header, files = m.read_asar(PATH)
rel = 'modules/riotPatchSdk.js'
text = files[rel].decode('utf-8', 'ignore')
root = p._parse(text).root_node
funcs = p._collect_functions(root, text)
req = p._require_map(root, text)
arrays = p._array_consts(root, text)
print('funcs', len(funcs), 'requires', list(req.items())[:3])

names = p._ipc_main_names(root, text)
print('names', sorted(names))

count = 0
for n in p._walk(root):
    if n.type != 'call_expression':
        continue
    fn = n.child_by_field_name('function')
    if fn is None or fn.type != 'member_expression':
        continue
    obj = fn.child_by_field_name('object')
    prop = fn.child_by_field_name('property')
    if obj is None or prop is None:
        continue
    if p._text_of(prop, text) not in ('handle', 'on', 'handleOnce'):
        continue
    if p._text_of(obj, text) not in names:
        continue
    channel = p._channel_of(n, text)
    handler = p._handler_of(n)
    count += 1
    if count <= 3:
        apis = set()
        if handler is not None:
            apis |= p._follow(handler, text, funcs, 0)
        print('  channel=', channel, 'handler=', handler.type if handler else None,
              'apis=', sorted(apis)[:4])
print('total ipc calls', count)
