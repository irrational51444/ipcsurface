"""precise 精查层（P1-7 的最小可行版）。

用 tree-sitter 重做「通道 → 危险 API」这条链，补粗扫的两个洞：
1. 跨文件：handler 把活委托给 require 进来的模块里的函数，粗扫跟不过去；
2. 解析：tree-sitter 零 ERROR，不靠手写补丁。

这是 opt-in（--precise），不进默认路径；装不上 tree-sitter 就不导入本模块，
粗扫照跑。产出是「更强一档证据」，永远不叫「确认」。

MVP 范围（诚实）：
- 认 ipcMain.handle/on 的字面量通道名；
- 同一个文件里，handler 调的函数一层层跟（有界深度）；
- require('...') 解析成文件，跟到被 require 的文件里再跟函数；
- 危险 API 判定沿用 jssem.DANGER。

不做（留给下一版）：成员方法调用（this.x() 到 class 里）、别名传播、字段级污点。
"""
import os

try:
    from tree_sitter import Language, Parser
    import tree_sitter_javascript
    _LANG = Language(tree_sitter_javascript.language())
    _PARSER = Parser(_LANG)
    AVAILABLE = True
except Exception:  # noqa: BLE001 —— 装不上就不导入，别卡死默认路径
    AVAILABLE = False

from jssem import DANGER  # noqa: E402


DANGER_SET = set(DANGER)

# `existsSync` 在粗扫的危险表里，但它只回答「在不在」，不读不写不执行。
# 精扫把它剔出去：它不是 sink，算进去只会让一堆纯查询型通道看着像危险通道。
# 粗扫那份表不动——那是历史口径，动它会把一大堆基准数字全打乱。
NOT_A_SINK = {'existsSync'}
_MAX_DEPTH = 8


def _children(node):
    for c in node.children:
        yield c


def _walk(node):
    yield node
    for c in node.children:
        yield from _walk(c)


_BYTE_CACHE = {}


def _text_of(node, text):
    """取节点源码。

    tree-sitter 的 `start_byte`/`end_byte` 是 **UTF-8 字节偏移**（`_parse` 传进去的是
    `text.encode("utf-8")`），而 `text` 是 str。直接 `text[a:b]` 是按字符切——
    文件里只要有一个中文注释，后面全体错位，取出来的标识符是乱码（`function`
    变成 `funct`），跟 `ipcMain` 比永远不等。

    dsh 的 `lib/main.js` 就是这样一条通道都认不出来的：文本里明明有
    `ipcMain.handle(...)`，AST 里取出来的对象名却是乱码。

    按字节切，编码结果缓存起来（`_follow` 会调这个函数几千次，每次都
    encode 整个文件受不了）。
    """
    cached = _BYTE_CACHE.get(id(text))
    if cached is None or cached[0] is not text:
        cached = (text, text.encode('utf-8', 'ignore'))
        _BYTE_CACHE[id(text)] = cached
    return cached[1][node.start_byte:node.end_byte].decode('utf-8', 'ignore')


def _parse(text):
    return _PARSER.parse(text.encode('utf-8', 'ignore'))


def _is_call(node):
    return node.type in ('call_expression',)


def _callee_plain(node, text):
    """只有 `f()` 这种裸名调用才返回名字，`obj.f()` 一律返回 None。

    跨函数追踪必须分这个：`browserGuests.acquire()` 的 `acquire` 只是方法名，
    把它当成本文件里的顶层函数 `acquire` 去追，追出来的危险 API 全是别人的。
    """
    fn = node.child_by_field_name('function')
    if fn is None or fn.type != 'identifier':
        return None
    return _text_of(fn, text)


def _callee_name(node, text):
    """调用点的被调函数名：f() / m.f() / obj['f']() 都取最后一段。"""
    fn = node.child_by_field_name('function')
    if fn is None:
        return None
    if fn.type == 'identifier':
        return _text_of(fn, text)
    if fn.type == 'member_expression':
        prop = fn.child_by_field_name('property')
        if prop is not None:
            return _text_of(prop, text)
    if fn.type == 'subscript_expression':
        # obj['name'] → 取字符串
        for c in _walk(fn):
            if c.type == 'string' and c.parent.type == 'subscript_expression':
                v = _text_of(c, text)[1:-1]
                return v
    return None


def _call_receiver(node, text):
    """m.f() 的接收者 m；f() 返回 None。"""
    fn = node.child_by_field_name('function')
    if fn is None or fn.type != 'member_expression':
        return None
    obj = fn.child_by_field_name('object')
    return _text_of(obj, text) if obj is not None else None


def _find_danger_calls(node, text):
    """这个子树里直接触到危险 API 的名字集合。"""
    found = set()
    for n in _walk(node):
        if n.type == 'call_expression':
            name = _callee_name(n, text)
            if name in DANGER_SET and name not in NOT_A_SINK:
                found.add(name)
    return found


def _ipc_main_names(root, text):
    """本文件里 `ipcMain` 的本地名字：别名（`const {ipcMain: s} = ...`）和原名。"""
    names = {'ipcMain'}
    for n in _walk(root):
        if n.type != 'variable_declarator':
            continue
        name = n.child_by_field_name('name')
        value = n.child_by_field_name('value')
        if name is None or name.type != 'object_pattern':
            continue
        # 不要求右边是 `require(...)`：压缩产物里是 webpack 的 `n(4482)`，
        # 一个 'require' 字样都没有。只要解构里出现 ipcMain 键就认。
        if value is None:
            continue
        for p in _walk(name):
            if p.type != 'pair_pattern':
                continue
            key = p.child_by_field_name('key')
            val = p.child_by_field_name('value')
            if key is None or val is None:
                continue
            if _text_of(key, text) == 'ipcMain':
                names.add(_text_of(val, text))
    return names


def _collect_classes(root, text):
    """{类名: {方法名: 方法体}}。"""
    classes = {}
    for n in _walk(root):
        if n.type != 'class_declaration':
            continue
        name = n.child_by_field_name('name')
        body = n.child_by_field_name('body')
        if name is None or body is None:
            continue
        methods = {}
        for m in body.named_children:
            if m.type != 'method_definition':
                continue
            mn = m.child_by_field_name('name')
            mb = m.child_by_field_name('body')
            if mn is not None and mb is not None:
                methods[_text_of(mn, text)] = mb
        if methods:
            classes[_text_of(name, text)] = methods
    return classes


def _collect_instances(root, text, classes):
    """`const app = new App()` → {app: App}，只收能对上类名的。"""
    out = {}
    for n in _walk(root):
        if n.type != 'variable_declarator':
            continue
        name = n.child_by_field_name('name')
        value = n.child_by_field_name('value')
        if name is None or value is None or value.type != 'new_expression':
            continue
        ctor = value.child_by_field_name('constructor')
        if ctor is None:
            continue
        cname = _text_of(ctor, text)
        if cname in classes:
            out[_text_of(name, text)] = cname
    return out


def _collect_functions(root, text):
    """文件里所有函数定义：名字 → 函数体节点。"""
    funcs = {}
    for n in _walk(root):
        if n.type in ('function_declaration', 'method_definition'):
            name = n.child_by_field_name('name')
            body = n.child_by_field_name('body')
            if name is not None and body is not None:
                funcs[_text_of(name, text)] = body
        elif n.type == 'lexical_declaration' or n.type == 'variable_declaration':
            # const f = (…) => {…} / const f = function(…) {…}
            decl = n
            for d in _walk(decl):
                if d.type in ('variable_declarator',):
                    name = d.child_by_field_name('name')
                    val = d.child_by_field_name('value')
                    if name is None or val is None:
                        continue
                    fname = _text_of(name, text)
                    if val.type in ('arrow_function', 'function_expression'):
                        body = val.child_by_field_name('body')
                        if body is not None:
                            funcs[fname] = body
    return funcs


def _follow(body_node, text, funcs, depth):
    """从 body 出发，追到危险 API。返回 API 集合。"""
    found = set(_find_danger_calls(body_node, text))
    if depth >= _MAX_DEPTH:
        return found
    for n in _walk(body_node):
        if n.type != 'call_expression':
            continue
        name = _callee_plain(n, text)
        if name and name in funcs:
            found |= _follow(funcs[name], text, funcs, depth + 1)
            continue
        # `obj.m()` / `this.m()`：只有当 obj 确实是 new 出来的那个类的实例，
        # 或者接收者是 this/super 时才追。否则 `x.save()` 的 save 会撞上
        # 同文件里一个毫不相干的顶层 save，追出来的全是别人的危险 API。
        fn = n.child_by_field_name('function')
        if fn is None or fn.type != 'member_expression':
            continue
        prop = fn.child_by_field_name('property')
        obj = fn.child_by_field_name('object')
        if prop is None:
            continue
        mname = _text_of(prop, text)
        classes = funcs.get('#classes') or {}
        insts = funcs.get('#vars') or {}
        target = None
        if obj is not None:
            oname = _text_of(obj, text)
            if oname in ('this', 'super'):
                # 当前类不知道，取第一个同名方法；宁可多追一层也不漏
                for cls in classes.values():
                    if mname in cls:
                        target = cls[mname]
                        break
            elif oname in insts:
                target = classes[insts[oname]].get(mname)
        if target is not None:
            found |= _follow(target, text, funcs, depth + 1)
    return found


def _channel_ex(node, text, tables=None):
    """ipcMain.handle('x', fn) 的第一个参数。字符串直接取；成员访问/下标取属性名。

    「取属性名」是启发式：抖音那种 `IPC_EVENTS.BRIDGE_MAIN_RECEIVE_EVENT` 里，
    常量名往往就等于字符串值（constanst.js 里就是这么写的）。这不是确认，是
    「成员访问的启发」，precise 结论永远标「更强一档证据」，不冒充字符串字面量。

    返回值带上证据档位，因为它决定这条报告能不能被追问：
      literal      —— 调用点写的就是字符串字面量
      const-table  —— 同文件里有 `const X = {k: '真名'}`，成员访问查表还原
      heuristic    —— 查不到表，只能拿属性名当通道名（会错，所以要标出来）

    dsh 就是栽在这里：`ipcMain.handle(DESKTOP_IPC.fileSave, ...)`，
    表在同文件里，早先只拿到 `fileSave`，粗扫拿到的是 `dsh-desktop:file-save`，
    两边永远对不上，还被当成「精扫漏报」。
    """
    args = node.child_by_field_name('arguments')
    if args is None:
        return None
    first = None
    for c in args.named_children:
        first = c
        break
    if first is None:
        return None
    if first.type == 'string':
        return _text_of(first, text)[1:-1], 'literal'
    if first.type == 'member_expression':
        obj = first.child_by_field_name('object')
        prop = first.child_by_field_name('property')
        propname = _text_of(prop, text) if prop is not None else None
        if not propname:
            return None
        if tables and obj is not None:
            hit = tables.get(_text_of(obj, text), {}).get(propname)
            if hit:
                return hit, 'const-table'
        return propname, 'heuristic'
    if first.type == 'subscript_expression':
        for c in _walk(first):
            if c.type == 'string' and c.parent.type == 'subscript_expression':
                return _text_of(c, text)[1:-1], 'literal'
        return None
    return None


def _object_const_strings(root, text):
    """`const X = {k: '真名'}` → {X: {k: '真名'}}。

    只为把 `ipcMain.handle(DESKTOP_IPC.fileSave, ...)` 还原成真通道名。
    不收 value 不是字符串的项：那种还原不出来，就该老实标 heuristic。
    """
    tables = {}
    for n in _walk(root):
        if n.type not in ('lexical_declaration', 'variable_declaration'):
            continue
        for d in n.named_children:
            if d.type != 'variable_declarator':
                continue
            name = d.child_by_field_name('name')
            value = d.child_by_field_name('value')
            if name is None or value is None or value.type != 'object':
                continue
            mapping = {}
            for pair in value.named_children:
                if pair.type != 'pair':
                    continue
                k = pair.child_by_field_name('key')
                v = pair.child_by_field_name('value')
                if k is None or v is None or v.type != 'string':
                    continue
                key = _text_of(k, text)
                if key[:1] in ('"', "'", '`'):
                    key = key[1:-1]
                mapping[key] = _text_of(v, text)[1:-1]
            if mapping:
                tables[_text_of(name, text)] = mapping
    return tables


def _channel_of(node, text, tables=None):
    """老接口：只要通道名。"""
    got = _channel_ex(node, text, tables)
    return got[0] if got else None


def _handler_of(node):
    """ipcMain.handle('x', fn) 的 fn（函数或箭头）。"""
    args = node.child_by_field_name('arguments')
    if args is None:
        return None
    named = args.named_children
    if len(named) < 2:
        return None
    h = named[1]
    # `ipcMain.on("x", (async (e, o) => {...}))`：handler 外面套了一层括号，
    # 类型是 `parenthesized_expression`。不剥这一层就认不出 handler，
    # ACLOS 的 286 条通道因此全被跳过（一条不剩）。
    guard = 0
    while h.type == 'parenthesized_expression' and guard < 4:
        inner = h.named_children
        if not inner:
            break
        h = inner[0]
        guard += 1
    if h.type in ('arrow_function', 'function_expression', 'function_declaration'):
        # 不能返回 body：`() => t` 的 body 只是个标识符 `t`，
        # 被当成 handler 名去 funcs 里找，找不到就误判成「未判定」。
        # ACLOS 的 get-bugly-config 就是这么被冤枉的。
        # 返回函数节点本身，_follow 会自己走进函数体。
        return h
    if h.type == 'identifier':
        return h  # 名字，交给 _follow 去 funcs 里找
    return h


def _array_consts(root, text):
    """const x = ['a','b'] → {x: ['a','b']}，供循环枚举展开用。"""
    arrays = {}
    for n in _walk(root):
        if n.type not in ('lexical_declaration', 'variable_declaration'):
            continue
        for d in n.named_children:
            if d.type != 'variable_declarator':
                continue
            name = d.child_by_field_name('name')
            value = d.child_by_field_name('value')
            if name is None or value is None or value.type != 'array':
                continue
            items = []
            ok = True
            for c in value.named_children:
                if c.type == 'string':
                    items.append(_text_of(c, text)[1:-1])
                else:
                    ok = False
                    break
            if ok:
                arrays[_text_of(name, text)] = items
    return arrays


def _for_of_channels(node, text, arrays):
    """for (const x of [...]) { ipcMain.on(x, fn) } → [(通道名, handler)]。

    只展开「字面量数组 + ipcMain 用循环变量当通道名」这一种；迭代对象是变量
    时查 arrays 表（const x = [...]）。for...in 不展开（遍历的是对象 key，不是
    字面量通道清单）。
    """
    if node.type != 'for_in_statement':
        return []
    op = node.child_by_field_name('operator')
    if op is not None and _text_of(op, text) == 'in':
        return []
    left = node.child_by_field_name('left')
    right = node.child_by_field_name('right')
    body = node.child_by_field_name('body')
    if left is None or right is None or body is None:
        return []
    var = _text_of(left, text)
    if right.type == 'array':
        items = []
        for c in right.named_children:
            if c.type != 'string':
                return []
            items.append(_text_of(c, text)[1:-1])
    elif right.type == 'identifier':
        items = arrays.get(_text_of(right, text))
        if items is None:
            return []
    else:
        return []
    if not items:
        return []
    # 循环体里找 ipcMain.on/handle(var, fn)
    handler = None
    for n in _walk(body):
        if n.type != 'call_expression':
            continue
        fn = n.child_by_field_name('function')
        if fn is None or fn.type != 'member_expression':
            continue
        obj = fn.child_by_field_name('object')
        prop = fn.child_by_field_name('property')
        if obj is None or prop is None:
            continue
        if _text_of(obj, text) != 'ipcMain':
            continue
        if _text_of(prop, text) not in ('handle', 'on', 'handleOnce'):
            continue
        args = n.child_by_field_name('arguments')
        if args is None or len(args.named_children) < 2:
            continue
        first = args.named_children[0]
        if _text_of(first, text) != var:
            continue
        handler = args.named_children[1]
        break
    if handler is None:
        return []
    return [(ch, handler) for ch in items]


def _require_map(root, text):
    """const fs = require('fs') / const x = require('./mod') → {var: path}"""
    req = {}
    for n in _walk(root):
        if n.type != 'call_expression':
            continue
        fn = n.child_by_field_name('function')
        if fn is None or _text_of(fn, text) != 'require':
            continue
        args = n.child_by_field_name('arguments')
        if args is None or not args.named_children:
            continue
        target = _text_of(args.named_children[0], text)
        if args.named_children[0].type == 'string':
            target = target[1:-1]
        # 找对应的赋值左值（const X = require(...)）
        parent = n.parent
        if parent is not None and parent.type == 'variable_declarator':
            name = parent.child_by_field_name('name')
            if name is not None:
                req[_text_of(name, text)] = target
    return req


def analyse_asar_precise(asar_path, text_ext=('.js', '.mjs', '.cjs'),
                          detailed=False):
    """precise 口径的 {channel: [危险 API]}。比粗扫多一层跨文件。"""
    if not AVAILABLE:
        raise SystemExit('tree-sitter 没装：pip install ipcsurface[precise]')

    import ipcsurface as core
    header, files = core.read_asar(asar_path)

    # 先把每个文件的（函数表, require 表, 文本）准备好
    modules = {}
    try:
        for rel in list(files.keys()):
            if not rel.endswith(text_ext):
                continue
            text = files[rel].decode('utf-8', 'ignore')
            root = _parse(text).root_node
            funcs = _collect_functions(root, text)
            classes = _collect_classes(root, text)
            if classes:
                # 塞进同一张表，省得给 _follow 加参数。'#' 开头的键不会跟
                # 标识符撞名，读到的人只认这两个固定键。
                funcs['#classes'] = classes
                funcs['#vars'] = _collect_instances(root, text, classes)
            modules[rel] = {
                'text': text,
                'root': root,
                'funcs': funcs,
                'requires': _require_map(root, text),
            }

        out = {}
        detail = {}
        for rel, mod in modules.items():
            text, root, funcs, req = mod['text'], mod['root'], mod['funcs'], mod['requires']
            arrays = _array_consts(root, text)
            tables = _object_const_strings(root, text)

            def record(channel, handler, via='literal'):
                if channel is None:
                    return
                # 三态，不是「有就记、没有就丢」：
                #   with_sink  —— 追到了危险 API，有证据
                #   no_sink    —— handler 看清楚了，里面确实没有危险调用
                #   unresolved —— handler 没解出来（跨模块引用 / 认不出的形态）
                # `unresolved` 必须显式存在。以前 `if apis:` 把它当空值吞掉，
                # 结果「没查到」被读成「没有」——安全工具里这是最坏的一种静默。
                status = 'unresolved'
                apis = set()
                direct = set()
                if handler is None:
                    status = 'unresolved'
                elif handler.type == 'identifier':
                    name = _text_of(handler, text)
                    if name in funcs:
                        apis |= _follow(funcs[name], text, funcs, 0)
                        status = 'with_sink' if apis else 'no_sink'
                    else:
                        status = 'unresolved'   # handler 是外部引用，解不出
                elif handler.type in ('arrow_function', 'function_expression',
                                      'function_declaration'):
                    apis |= _follow(handler, text, funcs, 0)
                    status = 'with_sink' if apis else 'no_sink'
                else:
                    # `handlers.save` 这种「成员访问当 handler」：函数体解不出来。
                    # 「没查到危险 API」不等于「干净」，只能标未判定。
                    # 跨文件能接上的话，_cross_file 会补进 apis。
                    apis |= _follow(handler, text, funcs, 0)
                    status = 'with_sink' if apis else 'unresolved'
                # 跨文件：handler 里 require 进来的模块函数，再跟一层
                if handler is not None:
                    body = handler
                    if handler.type in ('arrow_function', 'function_expression',
                                        'function_declaration'):
                        body = handler.child_by_field_name('body') or handler
                    direct = _find_danger_calls(body, text)
                    apis |= _cross_file(handler, text, req, modules, rel)
                if apis:
                    status = 'with_sink'
                    out.setdefault(channel, set()).update(apis)
                # 同一通道可能在多处注册（handle + 事件转发 + removeHandler 之类）。
                # 后写的直接覆盖先写的，会把「有证据」抹成「未判定」——
                # 这又是一次无声丢失。按严重度就高不就低，证据取并集。
                entry = {'status': status,
                         'via': via,
                         'direct': sorted(direct),
                         'apis': sorted(apis),
                         'file': rel,
                         'offset': (handler.start_byte if handler is not None else None)}
                prev = detail.get(channel)
                if prev is None:
                    detail[channel] = entry
                else:
                    rank = {'no_sink': 0, 'unresolved': 1, 'with_sink': 2}
                    worse = entry if rank[entry['status']] > rank[prev['status']] else prev
                    via_rank = {'heuristic': 0, 'const-table': 1, 'literal': 2}
                    best_via = (entry['via'] if via_rank[entry['via']] > via_rank[prev['via']]
                                else prev['via'])
                    detail[channel] = {
                        'status': worse['status'],
                        'via': best_via,
                        'apis': sorted(set(prev['apis']) | set(entry['apis'])),
                        'file': worse['file'],
                        'offset': worse['offset'],
                        'sites': (prev.get('sites') or 1) + 1,
                    }

            # 别名只算一次。放进循环里就是 O(n²)——4MB 文件上直接跑满 10 分钟超时。
            ipc_names = _ipc_main_names(root, text)
            for n in _walk(root):
                # 循环枚举：for (const x of [...]) { ipcMain.on(x, fn) }
                if n.type == 'for_in_statement':
                    for channel, handler in _for_of_channels(n, text, arrays):
                        record(channel, handler)
                    continue
                if n.type != 'call_expression':
                    continue
                fn = n.child_by_field_name('function')
                if fn is None:
                    continue
                # 只认 ipcMain.handle / ipcMain.on / ipcMain.handleOnce
                if fn.type == 'member_expression':
                    obj = fn.child_by_field_name('object')
                    prop = fn.child_by_field_name('property')
                    if obj is None or prop is None:
                        continue
                    # 三种形态都要认：
                    #   `ipcMain.handle(...)`          —— 裸名
                    #   `s.handle(...)`                —— 解构别名
                    #   `l.ipcMain.handle(...)`        —— 命名空间取属性
                    # obsidian 用的正是第三种，47 条通道全挂在 `l.ipcMain` 上；
                    # 早先只认前两种，于是整个包扫出 0 条通道。
                    obj_name = _text_of(obj, text)
                    if obj_name not in ipc_names:
                        if not (obj.type == 'member_expression'
                                and obj_name.endswith('.ipcMain')):
                            continue
                    if _text_of(prop, text) not in ('handle', 'on', 'handleOnce'):
                        continue
                else:
                    continue
                got = _channel_ex(n, text, tables)
                if not got:
                    continue
                channel, via = got
                handler = _handler_of(n)
                record(channel, handler, via)
        if detailed:
            return detail
        # 默认接口只返回「有证据」的那部分，老调用方不受影响。
        return {k: sorted(v) for k, v in out.items()}
    finally:
        files.close()


def _cross_file(handler_node, text, req, modules, cur_rel, depth=0):
    """handler 里调用的函数，若是 require 进来的模块，去那个文件里追。"""
    if depth >= 3:
        return set()
    found = set()
    for n in _walk(handler_node):
        if n.type != 'call_expression':
            continue
        receiver = _call_receiver(n, text)
        name = _callee_name(n, text)
        if not receiver or not name or receiver not in req:
            continue
        target = req[receiver]
        if not target.startswith('.'):
            continue  # 只跟项目内相对路径，不追 node_modules
        # 解析相对路径 → 模块 key
        base = os.path.dirname(cur_rel)
        norm = os.path.normpath(os.path.join(base, target))
        for suffix in ('', '.js', '/index.js'):
            key = (norm + suffix).replace('\\', '/')
            if key in modules:
                mod = modules[key]
                body = mod['funcs'].get(name)
                if body is not None:
                    found |= _follow(body, mod['text'], mod['funcs'], 0)
                    # 被追的模块里可能还有 require，再往下一层
                    found |= _cross_file(body, mod['text'], mod['requires'],
                                         modules, key, depth + 1)
                break
    return found
