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
_MAX_DEPTH = 8


def _children(node):
    for c in node.children:
        yield c


def _walk(node):
    yield node
    for c in node.children:
        yield from _walk(c)


def _text_of(node, text):
    return text[node.start_byte:node.end_byte]


def _parse(text):
    return _PARSER.parse(text.encode('utf-8', 'ignore'))


def _is_call(node):
    return node.type in ('call_expression',)


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
            if name in DANGER_SET:
                found.add(name)
    return found


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
        name = _callee_name(n, text)
        if name and name in funcs:
            found |= _follow(funcs[name], text, funcs, depth + 1)
    return found


def _channel_of(node, text):
    """ipcMain.handle('x', fn) 的第一个参数。字符串直接取；成员访问/下标取属性名。

    「取属性名」是启发式：抖音那种 `IPC_EVENTS.BRIDGE_MAIN_RECEIVE_EVENT` 里，
    常量名往往就等于字符串值（constanst.js 里就是这么写的）。这不是确认，是
    「成员访问的启发」，precise 结论永远标「更强一档证据」，不冒充字符串字面量。
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
        return _text_of(first, text)[1:-1]
    if first.type == 'member_expression':
        prop = first.child_by_field_name('property')
        return _text_of(prop, text) if prop is not None else None
    if first.type == 'subscript_expression':
        for c in _walk(first):
            if c.type == 'string' and c.parent.type == 'subscript_expression':
                return _text_of(c, text)[1:-1]
        return None
    return None


def _handler_of(node):
    """ipcMain.handle('x', fn) 的 fn（函数或箭头）。"""
    args = node.child_by_field_name('arguments')
    if args is None:
        return None
    named = args.named_children
    if len(named) < 2:
        return None
    h = named[1]
    if h.type in ('arrow_function', 'function_expression'):
        return h.child_by_field_name('body')
    if h.type == 'identifier':
        return h  # 名字，交给 _follow 去 funcs 里找
    return None


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


def analyse_asar_precise(asar_path, text_ext=('.js', '.mjs', '.cjs')):
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
            modules[rel] = {
                'text': text,
                'root': root,
                'funcs': _collect_functions(root, text),
                'requires': _require_map(root, text),
            }

        out = {}
        for rel, mod in modules.items():
            text, root, funcs, req = mod['text'], mod['root'], mod['funcs'], mod['requires']
            arrays = _array_consts(root, text)

            def record(channel, handler):
                if channel is None or handler is None:
                    return
                apis = set()
                if handler.type == 'identifier':
                    name = _text_of(handler, text)
                    if name in funcs:
                        apis |= _follow(funcs[name], text, funcs, 0)
                else:
                    apis |= _follow(handler, text, funcs, 0)
                # 跨文件：handler 里 require 进来的模块函数，再跟一层
                apis |= _cross_file(handler, text, req, modules, rel)
                if apis:
                    out.setdefault(channel, set()).update(apis)

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
                    if _text_of(obj, text) != 'ipcMain':
                        continue
                    if _text_of(prop, text) not in ('handle', 'on', 'handleOnce'):
                        continue
                else:
                    continue
                channel = _channel_of(n, text)
                if not channel:
                    continue
                handler = _handler_of(n)
                if handler is None:
                    continue
                record(channel, handler)
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
