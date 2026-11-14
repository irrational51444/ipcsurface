"""jssem —— 第一层语义：作用域、赋值、以及「参数能不能流到危险 API」。

只做一件事，但要做细：同函数内，参数经局部变量转手（`const p = payload.path`）
再进危险调用，也算流到了。做法是在函数体的 token 上做赋值传播，迭代到不动点。

不做：跨函数参数映射、类型推断、原型链、eval、分支敏感。
这些一律不算「安全」，报告里必须写「未分析」——没分析不等于没问题。
"""

import os

DANGER_KINDS = {
    # 真包里核对时发现少了几样：Obsidian 的 vault-open 是 mkdirSync、copy-asar 是 copyFileSync，
    # 这两个都不在旧表里，于是「能碰文件」的能力被漏掉了。
    '文件写': ('writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
             'createWriteStream', 'unlink', 'unlinkSync', 'rmSync', 'rename', 'renameSync',
             'copyFile', 'copyFileSync', 'mkdir', 'mkdirSync', 'mkdtemp', 'mkdtempSync',
             'rmdir', 'rmdirSync', 'truncate', 'truncateSync'),
    '文件读': ('readFile', 'readFileSync', 'createReadStream', 'readdir', 'readdirSync',
             'readdirSync', 'lstat', 'stat', 'existsSync'),
    '命令执行': ('exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync'),
    '网络': ('fetch', 'request'),
    '动态求值': ('eval', 'Function'),
}
DANGER = tuple(name for group in DANGER_KINDS.values() for name in group)
# 只有这几个名字会被别的对象占用（RegExp.exec、bare fetch 少见但要认）：
# fs.readFileSync 不会被别的对象同名占用，所以不查接收者。
AMBIGUOUS = ('exec', 'execFile', 'execFileSync', 'fetch', 'request')


def danger_kind(name):
    """这个调用属于哪一类。分开报的意义：读文件、执行命令、发网络请求，
    严重程度和后果完全不同，混成一个「危险 API」等于没说。"""
    for kind, names in DANGER_KINDS.items():
        if name in names:
            return kind
    return '其它'
DECL = ('const', 'let', 'var')
ASSIGN_OPS = ('=', '+=', '-=', '*=', '/=')


def _end_of_statement(tokens, i, limit):
    depth = 0
    while i < limit:
        text = tokens[i].text
        if text in '([{':
            depth += 1
        elif text in ')]}':
            if depth == 0:
                return i
            depth -= 1
        elif text in (';', ',') and depth == 0:
            return i
        i += 1
    return limit


def scope_index(tokens):
    """块的父子关系 + 每个 let/var/const 声明落在哪个块。

    JS 的函数作用域和块作用域在压缩产物里都长成 `{...}`，所以只要记住
    「这个 token 属于哪个 `{`」，再由 `parent` 一路往上，就能判断一个声明
    对某个位置可不可见。这不是完整的词法作用域分析（`catch`、`for` 头里的
    声明、`var` 的提升都没建模），但它能回答一个问题：**这个短名在这儿
    指的是不是那个赋值**。

    返回 (parent, blocks, binds)：
      parent[块起始下标] = 该块的父块起始下标，顶层是 0；
      blocks[i]          = token i 所在块的起始下标；
      binds              = [(名字, 声明下标, 值起始下标, 所在块)]。
    """
    blocks = [0] * len(tokens)
    parent = {0: None}
    stack = []
    binds = []
    for i, tok in enumerate(tokens):
        blocks[i] = stack[-1] if stack else 0
        text = tok.text
        # 只跟花括号：圆括号和方括号不构成作用域，混进来会把父子链截断。
        if text == '{':
            parent[i] = stack[-1] if stack else 0
            stack.append(i)
        elif text == '}':
            if stack:
                stack.pop()
        elif text in ('let', 'var', 'const'):
            j = i + 1
            if (j + 1 < len(tokens) and tokens[j].kind == 'ident'
                    and tokens[j + 1].text == '='):
                binds.append((tokens[j].text, i, j + 2, blocks[i]))
    return parent, blocks, binds


def resolve_root(tokens, index, pos, name):
    """在 pos 处按块作用域找 name 最近的外层声明。

    返回值 (声明下标, rhs tokens)；找不到返回 None。
    只看 `let/var/const name = ...`，普通赋值不算——那可能是在改别人的值。
    """
    parent, blocks, binds = index
    visible = set()
    block = blocks[pos] if pos < len(blocks) else 0
    while block is not None:
        visible.add(block)
        block = parent.get(block)
    best = None
    for bname, decl_i, rhs_start, bblock in binds:
        if bname != name or decl_i >= pos or bblock not in visible:
            continue
        if best is None or decl_i > best[0]:
            best = (decl_i, rhs_start)
    if best is None:
        return None
    rhs = []
    for r in range(best[1], min(best[1] + 16, len(tokens))):
        if tokens[r].text in (';', ','):
            break
        rhs.append(tokens[r])
    return best[0], rhs


def classify_root(rhs):
    """根的形状：字面量 / 已知目录 / 其他表达式。

    `app.getPath("userData")` 这类算已知目录——它不是字面量，但它在 Electron
    里就是固定位置，`join` 到它底下不会跑出用户数据目录（除非带 `..`）。
    """
    if not rhs:
        return ('expr', None)
    if len(rhs) == 1 and rhs[0].kind == 'string':
        return ('literal', rhs[0].text.strip('"\'`'))
    texts = [t.text for t in rhs]
    if 'getPath' in texts or 'getAppPath' in texts:
        for t in rhs:
            if t.kind == 'string':
                return ('known-dir', t.text.strip('"\'`'))
    return ('expr', None)


_NOT_A_CALL = frozenset((
    'if', 'for', 'while', 'switch', 'catch', 'return', 'typeof', 'delete',
    'do', 'else', 'with', 'function', 'void', 'await', 'yield', 'in', 'of',
))


def state_writes_interproc(tokens, start, end, tainted, defs, depth=2):
    """跨函数写状态：`helper(C, i)`，而 helper 里把某个形参写进了字段。

    只跟**同文件里能直接找到定义**的函数。形参和实参按位置对齐，个数对不上
    就不跟——形状不对的时候猜，比不报更坏。

    返回 [(被调函数名, 字段名, 来源形参, 写入偏移, (读点...))]。
    位置是在被调函数体里的偏移，同文件，切片段用同一份源码。
    """
    if depth <= 0:
        # 深度到顶。这里不是「没找到」，是「没往下找」——两件事必须分开记。
        # 只在真的还有得跟时才记一笔：体内还有对同文件函数的调用、且实参里有脏值。
        if _truncated is not None and _still_has_hop(tokens, start, end, defs,
                                                    tainted):
            _truncated.append((start, end))
        return []
    by_name = {}
    for d in defs:
        by_name.setdefault(d['name'], d)
    out = []
    limit = min(end, len(tokens) - 1)
    for i in range(start, limit):
        tok = tokens[i]
        if tok.kind != 'ident' or tok.text not in by_name:
            continue
        if i >= 1 and tokens[i - 1].text == '.':
            continue          # 成员调用 `obj.helper(...)` 不知道 obj 是谁
        if tokens[i + 1].text != '(':
            continue
        target = by_name[tok.text]
        params = target.get('params') or []
        if not params:
            continue
        arg_lists, _close = _split_args(tokens, i + 1)
        if len(arg_lists) != len(params):
            continue
        sub = set()
        for pname, arg in zip(params, arg_lists):
            if any(t.kind == 'ident' and t.text in tainted for t in arg):
                sub.add(pname)
        if not sub:
            continue
        for field, src_name, off, reads in state_writes(
                tokens, target['body_start'], target['body_end'], sub):
            out.append((tok.text, field, src_name, off, reads))
    return out


MODULE_SHAPES = ('arrow', 'named-arrow', 'function', 'assigned-function')


def find_modules(tokens):
    """webpack 模块表：`134:(e,t,n)=>{...}` / `12:e=>{...}` / `7:function(){...}`。

    压缩产物里模块就是「一个数字 id 加一个函数体」，所以配平花括号就能拿到边界。
    四种写法都认：

      - `134:(e,t,n)=>{`   箭头函数带参数表
      - `12:e=>{`          箭头函数单参
      - `7:function(e,t,n){`
      - `7:e=function(e){` 先赋给形参再写

    返回 [(id, params, body_open, body_close, shape)]，body_open 是 `{` 的下标。
    认不出函数体的 id 直接跳过——宁缺，不乱给一个边界。
    """
    out = []
    n = len(tokens)
    i = 0
    while i < n - 4:
        tok = tokens[i]
        if not tok.text.isdigit() or tokens[i + 1].text != ':':
            i += 1
            continue
        # `switch` 的 `case 0:t=function(){...}` 和模块表长得一样。
        # 模块 id 前面只可能是 `{` 或 `,`；`case` 是个标识符，正好把它挡掉。
        if i == 0 or tokens[i - 1].text not in ('{', ','):
            i += 1
            continue
        j = i + 2
        shape = None
        params = []
        if tokens[j].kind == 'ident' and tokens[j + 1].text == '=' \
                and tokens[j + 2].text == 'function':
            shape = 'assigned-function'
            j += 2
        if tokens[j].text == 'function':
            shape = shape or 'function'
            j += 1
            if tokens[j].text == '(':
                close = _close_paren(tokens, j)
                params = [t.text for t in tokens[j + 1:close] if t.kind == 'ident']
                j = close + 1
        elif tokens[j].text == '(':
            close = _close_paren(tokens, j)
            params = [t.text for t in tokens[j + 1:close] if t.kind == 'ident']
            j = close + 1
            if tokens[j].text != '=>':
                i += 1
                continue
            shape = shape or 'arrow'
            j += 1
        elif tokens[j].kind == 'ident':
            params = [tokens[j].text]
            j += 1
            if tokens[j].text != '=>':
                i += 1
                continue
            shape = shape or 'named-arrow'
            j += 1
        else:
            i += 1
            continue
        if j >= n or tokens[j].text != '{':
            i += 1
            continue
        depth = 0
        end = None
        for p in range(j, n):
            if tokens[p].text == '{':
                depth += 1
            elif tokens[p].text == '}':
                depth -= 1
                if depth == 0:
                    end = p
                    break
        if end is None:
            i += 1
            continue
        out.append((tok.text, params, j, end, shape))
        i = end
    return out


def module_edges(tokens, modules):
    """模块之间的依赖边：模块里的 `n(8813)` 表示它 require 了 8813。

    只认「调用名就是本模块的第三个形参」这一种形状（webpack 的惯例），
    并且只连到确实存在的模块 id 上。连不上的就丢掉，不猜。
    """
    by_id = {mid for mid, _p, _o, _c, _s in modules}
    params_of = {mid: params for mid, params, _o, _c, _s in modules}
    edges = []
    for mid, params, body_open, body_close, _shape in modules:
        if len(params) < 3:
            continue
        req = params[2]
        for k in range(body_open + 1, body_close - 3):
            if tokens[k].kind != 'ident' or tokens[k].text != req:
                continue
            if tokens[k + 1].text != '(' or not tokens[k + 2].text.isdigit():
                continue
            if tokens[k + 3].text != ')':
                continue
            target = tokens[k + 2].text
            if target in by_id:
                edges.append((mid, target))
    return sorted(set(edges))


def module_of(modules, index):
    """某个 token 属于哪个模块；不在任何模块里返回 None。"""
    for mid, _params, body_open, body_close, _shape in modules:
        if body_open <= index <= body_close:
            return mid
    return None


def _literal_array(tokens, body_open, body_close, name):
    """找 `name = ["a", "b", ...]`，把字符串元素摊出来。

    只认字面量数组。数组里混了变量、函数调用、展开的，一律返回空——
    那种算不出来，报一半比不报更坏。
    """
    for k in range(body_open + 1, body_close - 3):
        if tokens[k].kind != 'ident' or tokens[k].text != name:
            continue
        if tokens[k + 1].text != '=':
            continue
        if tokens[k + 2].text == '[':
            close = _close_paren(tokens, k + 2)
            items = []
            for tok in tokens[k + 3:close]:
                if tok.text == ',':
                    continue
                if tok.kind != 'string':
                    return []
                items.append(tok.text.strip('"\'`'))
            return items
        # `A.concat(B, C)`：左右两边都是字面量数组时，拼起来算。
        # 任何一边算不出来，整条返回空——只报一半比不报更坏。
        if (tokens[k + 2].kind == 'ident' and tokens[k + 3].text == '.'
                and tokens[k + 4].text == 'concat' and tokens[k + 5].text == '('):
            left = _literal_array(tokens, body_open, body_close, tokens[k + 2].text)
            if not left:
                return []
            close = _close_paren(tokens, k + 5)
            for tok in tokens[k + 6:close]:
                if tok.kind != 'ident':
                    continue
                right = _literal_array(tokens, body_open, body_close, tok.text)
                if not right:
                    return []
                left = left + right
            return left
    return []


def module_exports(tokens, modules, external_consts=None):
    """每个模块导出了什么。四种写法都认：

      1. `t.X = ...`           exports 形参上挂成员；
      2. `t["X"] = ...`        下标写法，索引是字符串字面量；
      3. `e.exports.X = ...`   module.exports 上直接挂；
      4. `e.exports = {X: ...}` 整体换成对象字面量。

    外加一层 receiver 别名：`const e = exports; e.X = ...` 里的 `e` 也算导出对象。
    动态属性名（`t[name]`）直接放弃——静态不知道 `name` 是什么。

    `external_consts` 是调用方从别的文件解出来的常量（`const K = require("./c").CH`），
    并进本地常量表一起用。

    返回 {(模块 id, 出口名): (rhs tokens, 字符偏移)}。
    """
    out = {}
    # 没有模块表的文件（普通 CommonJS）也当一层：整个文件就是「模块体」，
    # 导出对象叫 `exports`，模块对象叫 `module`。不加这一条的话，
    # 跨文件跟到一个非打包的 handler.js 就什么都读不出来。
    if modules:
        spans = modules
    else:
        spans = [('file', ['module', 'exports', 'exports'], 0,
                  max(0, len(tokens) - 1), 'file')]
    for mid, params, body_open, body_close, _shape in spans:
        if len(params) < 3:
            continue
        exports_param = params[2]
        module_param = params[0]
        limit = body_close

        # 同模块的字符串常量表：`const K = "x"; exports[K] = ...`。
        # 这类「动态」属性名其实算得出来——它的值就在上面几行。
        consts = dict(external_consts or {})
        k = body_open + 1
        while k < limit:
            if tokens[k].text not in ('const', 'let', 'var'):
                k += 1
                continue
            # 一条声明里可能有多个：`let A = "a", B = "b";`。
            # 逐段收，碰到分号或别的形态就停。
            j = k + 1
            while j < body_close - 2:
                if (tokens[j].kind == 'ident' and tokens[j + 1].text == '='
                        and tokens[j + 2].kind == 'string'):
                    # `const K = "a" + "b"`：纯字面量拼接，拼完还是常量。
                    # 只要中间夹了变量或调用，就到此为止，不当常量用。
                    parts = [tokens[j + 2].text.strip('"\'`')]
                    q = j + 3
                    bad = False
                    while q < body_close:
                        if tokens[q].text != '+':
                            break
                        if q + 1 < body_close and tokens[q + 1].kind == 'string':
                            parts.append(tokens[q + 1].text.strip('"\'`'))
                            q += 2
                            continue
                        # `"a" + x`：拼了变量，这条就不算常量了。
                        # 只留前半截当成名字，等于编了一个不存在的通道名。
                        bad = True
                        break
                    if not bad:
                        consts.setdefault(tokens[j].text, ''.join(parts))
                    j = q
                elif tokens[j].text == ',':
                    j += 1
                else:
                    break
            k = j + 1

        # receiver 别名：`const e = exports;` 之后 `e.X = ...` 也是导出。
        receivers = {exports_param}
        for k in range(body_open + 1, limit):
            if k + 4 >= body_close:
                break
            if (tokens[k].text in ('const', 'var', 'let')
                    and tokens[k + 1].kind == 'ident'
                    and tokens[k + 2].text == '='
                    and tokens[k + 3].kind == 'ident'
                    and tokens[k + 3].text == exports_param):
                receivers.add(tokens[k + 1].text)

        for k in range(body_open + 1, limit):
            if k + 4 >= body_close:
                break
            tok = tokens[k]
            if tok.kind != 'ident' or tok.text not in receivers:
                continue
            # `exports = { X: ... }`：整体重赋值。不推荐，但真有人这么写，
            # 认不出来就等于整份导出表是空的。
            if tokens[k + 1].text == '=' and tokens[k + 2].text == '{':
                close = _close_paren(tokens, k + 2)
                for segment in _split_object_fields(tokens, k + 2, close):
                    if (len(segment) >= 2 and segment[0].kind in ('ident', 'string')
                            and segment[1].text == ':'):
                        out.setdefault((mid, segment[0].text.strip('"\'`')),
                                       (segment[2:], segment[0].start))
                continue
            if tokens[k + 1].text == '.' and tokens[k + 2].kind == 'ident':
                name = tokens[k + 2].text
                eq_at = k + 3
            elif (tokens[k + 1].text == '[' and tokens[k + 2].kind == 'string'
                    and tokens[k + 3].text == ']'):
                name = tokens[k + 2].text.strip('"\'`')
                eq_at = k + 4
            elif (tokens[k + 1].text == '[' and tokens[k + 2].kind == 'ident'
                    and tokens[k + 3].text == ']'):
                # `exports[K]`：K 在同模块里被赋成字符串字面量，就把它当名字。
                # 不在表里（来自参数、配置、函数返回值）就跳过——那种算不出来。
                name = consts.get(tokens[k + 2].text)
                if not name:
                    continue
                eq_at = k + 4
            else:
                continue
            if tokens[eq_at].text != '=':
                continue
            # 右值要用括号配平来切：函数体里本身有分号和逗号，
            # 数到第 16 个 token 或碰到第一个分号都会把函数体切碎，
            # 后面就再也找不到它的体区间了。
            stop = _end_of_statement(tokens, eq_at + 1, body_close)
            rhs = tokens[eq_at + 1:stop]
            out.setdefault((mid, name), (rhs, tok.start))

        # `module.exports.X = ...`
        for k in range(body_open + 1, limit):
            if k + 5 >= body_close:
                break
            if (tokens[k].kind != 'ident' or tokens[k].text != module_param
                    or tokens[k + 1].text != '.' or tokens[k + 2].text != 'exports'):
                continue
            if tokens[k + 3].text == '.' and tokens[k + 4].kind == 'ident' \
                    and tokens[k + 5].text == '=':
                stop = _end_of_statement(tokens, k + 6, body_close)
                rhs = tokens[k + 6:stop]
                out.setdefault((mid, tokens[k + 4].text), (rhs, tokens[k].start))
                continue
            if tokens[k + 3].text != '=':
                continue
            # `module.exports = class X { ... }`：导出一个类。
            # 记成类名（匿名就记 `default`），值为空——构造函数里有危险调用的话，
            # 那属于「实例化时才发生」，静态这层不追。
            if tokens[k + 4].text == 'class':
                cls_at = k + 5
                if cls_at < body_close and tokens[cls_at].kind == 'ident':
                    out.setdefault((mid, tokens[cls_at].text), ([], tokens[cls_at].start))
                else:
                    out.setdefault((mid, 'default'), ([], tokens[k + 4].start))
                continue
            if tokens[k + 4].text != '{':
                continue
            # `module.exports = { X: ..., Y: ... }`：按顶层逗号切开
            close = _close_paren(tokens, k + 4)
            for segment in _split_object_fields(tokens, k + 4, close):
                if (len(segment) >= 2 and segment[0].kind in ('ident', 'string')
                        and segment[1].text == ':'):
                    name = segment[0].text.strip('"\'`')
                    rhs = []
                    for r in segment[2:18]:
                        rhs.append(r)
                    out.setdefault((mid, name), (rhs, segment[0].start))

        # 配置驱动：`for (const op of OPS) exports[op] = ...`。
        # OPS 是同模块的字面量数组时，把它摊成具体名字——这种「动态」也能算。
        for k in range(body_open + 1, limit):
            if k + 6 >= body_close:
                break
            if tokens[k].text != 'for' or tokens[k + 1].text != '(':
                continue
            if not (tokens[k + 2].text in ('const', 'let', 'var')
                    and tokens[k + 3].kind == 'ident'
                    and tokens[k + 4].text in ('of', 'in')
                    and tokens[k + 5].kind == 'ident'):
                continue
            loop_var = tokens[k + 3].text
            array_name = tokens[k + 5].text
            items = _literal_array(tokens, body_open, body_close, array_name)
            if not items:
                continue
            close = _close_paren(tokens, k + 1)
            body_at = close + 1
            if body_at >= body_close or tokens[body_at].text != '{':
                continue
            body_end = _close_paren(tokens, body_at)
            uses = False
            for q in range(body_at, max(body_at, body_end - 3)):
                if (tokens[q].kind == 'ident' and tokens[q].text in receivers
                        and tokens[q + 1].text == '['
                        and tokens[q + 2].text == loop_var
                        and tokens[q + 3].text == ']'):
                    uses = True
                    break
            if not uses:
                continue
            for item in items:
                out.setdefault((mid, item), ([], tokens[k].start))
    return out


def _split_object_fields(tokens, open_at, close_at):
    """把 `{ a: ..., b: ... }` 按顶层逗号切成字段 token 列表。"""
    fields, current, depth = [], [], 0
    for tok in tokens[open_at + 1:close_at]:
        if tok.text in ('(', '[', '{'):
            depth += 1
        elif tok.text in (')', ']', '}'):
            depth -= 1
        if tok.text == ',' and depth == 0:
            fields.append(current)
            current = []
            continue
        current.append(tok)
    if current:
        fields.append(current)
    return [f for f in fields if f]


def esm_imports(tokens):
    """`import { A, B as C } from "./m"` → {本地名: (类型, spec, 原名)}。

    有了这张表，`ipcMain.handle("x", save)` 里的裸 `save` 才知道该去哪个文件找。
    只认具名导入、默认导入和 `import * as ns`；动态 `import()` 不算——那是运行时的事。
    """
    out = {}
    n = len(tokens)
    for i in range(n - 6):
        if tokens[i].text != 'import':
            continue
        j = i + 1
        if tokens[j].text == '*':
            if (j + 3 < n and tokens[j + 1].text == 'as'
                    and tokens[j + 2].kind == 'ident'
                    and tokens[j + 3].text == 'from'
                    and tokens[j + 4].kind == 'string'):
                out[tokens[j + 2].text] = ('*', tokens[j + 4].text.strip('"\'`'), None)
            continue
        if tokens[j].text == '{':
            close = _close_paren(tokens, j)
            if (close + 2 < n and tokens[close + 1].text == 'from'
                    and tokens[close + 2].kind == 'string'):
                spec = tokens[close + 2].text.strip('"\'`')
                k = j + 1
                while k < close:
                    if tokens[k].kind != 'ident':
                        k += 1
                        continue
                    name = tokens[k].text
                    local = name
                    if (k + 2 < close and tokens[k + 1].text == 'as'
                            and tokens[k + 2].kind == 'ident'):
                        local = tokens[k + 2].text
                        k += 3
                    else:
                        k += 1
                    out.setdefault(local, ('named', spec, name))
            continue
        if tokens[j].kind == 'ident':
            if (j + 2 < n and tokens[j + 1].text == 'from'
                    and tokens[j + 2].kind == 'string'):
                out[tokens[j].text] = ('default', tokens[j + 2].text.strip('"\'`'), None)
    return out


def esm_exports(tokens):
    """ESM 的导出：`export function x(){}` / `export const x = ...` / `export { x }`。

    只认写死的名字。`export default` 记成 `default`——它不是具名出口，
    但也确实导出了东西，别让调用方以为这是个空模块。
    """
    out = {}
    n = len(tokens)
    for i in range(n - 2):
        if tokens[i].text != 'export':
            continue
        j = i + 1
        if tokens[j].text == 'default':
            out.setdefault('default', (tokens[j + 1:j + 6], tokens[i].start))
            continue
        if tokens[j].text in ('function', 'class'):
            k = j + 1
            if k < n and tokens[k].text == '*':
                k += 1
            if k < n and tokens[k].kind == 'ident':
                out.setdefault(tokens[k].text, ([], tokens[i].start))
            continue
        if tokens[j].text in ('const', 'let', 'var'):
            k = j + 1
            if k < n and tokens[k].kind == 'ident':
                rhs = []
                for r in range(k + 2, min(k + 14, n)):
                    if tokens[r].text in (';', ','):
                        break
                    rhs.append(tokens[r])
                out.setdefault(tokens[k].text, (rhs, tokens[i].start))
            continue
        if tokens[j].text == '{':
            close = _close_paren(tokens, j)
            for tok in tokens[j + 1:close]:
                if tok.kind == 'ident' and tok.text != 'as':
                    out.setdefault(tok.text, ([], tok.start))
    return out


def resolve_required_path(rel, spec):
    """把 `require("./modA")` 解析成 asar 里的相对路径候选。

    只处理相对路径和带扩展名的写法。`require("electron")`、`require("fs")` 这类
    包名一律返回空——它们在包里没有源文件，硬解析只会猜错。

    返回候选列表，按可能性排序：`./a` → `a.js`、`a/index.js`。
    """
    if not spec or not spec.startswith('.'):
        return []
    directory = os.path.dirname(rel).replace('\\', '/')
    base = spec.replace('\\', '/')
    if directory:
        joined = _normpath(directory + '/' + base)
    else:
        joined = _normpath(base)
    if joined.endswith('.js') or joined.endswith('.json'):
        return [joined]
    return [joined + '.js', joined + '/index.js']


def _normpath(path):
    parts = []
    for piece in path.split('/'):
        if piece in ('', '.'):
            continue
        if piece == '..':
            if parts:
                parts.pop()
            continue
        parts.append(piece)
    return '/'.join(parts)


def require_target(rel, tokens, receiver):
    """在同文件里找 `receiver = require("./x")`，返回规范化后的目标路径。"""
    if not receiver:
        return None
    limit = len(tokens) - 6
    for i in range(1, max(1, limit)):
        if tokens[i].kind != 'ident' or tokens[i].text != receiver:
            continue
        if tokens[i + 1].text != '=':
            continue
        if tokens[i + 2].kind != 'ident' or tokens[i + 2].text != 'require':
            continue
        if tokens[i + 3].text != '(' or tokens[i + 4].kind != 'string':
            continue
        spec = tokens[i + 4].text.strip('"\'`')
        for candidate in resolve_required_path(rel, spec):
            yield candidate


def export_body(tokens, modules, rel, name, external_consts=None):
    """在目标文件的导出表里找 `name`，返回它的函数体区间。

    只认 rhs 是函数表达式或箭头函数的情况；rhs 是个标识符（`exports.a = impl`）
    就跟一层，跟不到就返回 None——不猜。
    """
    exports = module_exports(tokens, modules, external_consts)
    esm = esm_exports(tokens)
    hit = exports.get((None, name)) if False else None
    for (mid, ename), (rhs, _off) in exports.items():
        if ename == name:
            hit = rhs
            break
    if hit is None and name in esm:
        hit = esm[name][0]
    if not hit:
        # ESM 具名导出（`export function save(){}`）本身没有右值，
        # 函数名就是符号——去 function_defs 里按名字找体。
        import jsparse
        for d in jsparse.function_defs(tokens):
            if d['name'] == name:
                return (d['body_start'], d['body_end'])
        return None
    body = _body_of_rhs(tokens, hit)
    if not body:
        return None
    # `_body_of_rhs` 给的是 rhs 里的相对下标，换算成整份 token 的绝对下标。
    try:
        base = tokens.index(hit[0])
    except ValueError:
        return None
    return (base + body[0], base + body[1])


def _body_of_rhs(tokens, rhs):
    """从一段 rhs token 里找出函数体的 (start, end)；找不到返回 None。"""
    for i, tok in enumerate(rhs):
        if tok.text == 'function':
            j = i + 1
            if j < len(rhs) and rhs[j].kind == 'ident':
                j += 1
            if j < len(rhs) and rhs[j].text == '(':
                close = _close_paren(rhs, j)
                if close + 1 < len(rhs) and rhs[close + 1].text == '{':
                    end = _close_paren(rhs, close + 1)
                    return (close + 2, end - 1)
            continue
        if tok.text == '=' and i + 1 < len(rhs):
            # `= (…) => { … }`：箭头函数
            j = i + 1
            if rhs[j].text == '(':
                close = _close_paren(rhs, j)
                if close + 2 < len(rhs) and rhs[close + 1].text == '=>':
                    if rhs[close + 2].text == '{':
                        end = _close_paren(rhs, close + 2)
                        return (close + 3, end - 1)
    return None


def resolve_require_member(tokens, modules, exports, index):
    """`n(8813).CONST` 这种：在 index 处看是不是跨模块取成员，取得到就返回值。

    只认「调用名是本模块第三个形参、实参纯数字、后面紧跟 `.名字`」，
    并且那个名字真的在目标模块的导出表里。任何一环对不上都返回 None。
    """
    mod = module_of(modules, index)
    if mod is None:
        return None
    params = None
    for mid, p, body_open, body_close, _shape in modules:
        if mid == mod:
            params = p
            break
    if not params or len(params) < 3:
        return None
    req = params[2]
    for k in range(index, min(index + 40, len(tokens) - 5)):
        if tokens[k].kind != 'ident' or tokens[k].text != req:
            continue
        if tokens[k + 1].text != '(' or not tokens[k + 2].text.isdigit():
            continue
        if tokens[k + 3].text != ')' or tokens[k + 4].text != '.':
            continue
        if tokens[k + 5].kind != 'ident':
            continue
        hit = exports.get((tokens[k + 2].text, tokens[k + 5].text))
        if hit:
            return hit
    return None


def electron_ipc_aliases(tokens):
    """`const {ipcMain: a} = require("electron")` → `{'a'}`。

    压缩产物把 `ipcMain` 解构重命名之后，文件里再也不会出现 `ipcMain` 这个词，
    `ipcMain.handle(...)` 的字面匹配一条都认不出来。ACLOS 就是这样：45 个文件
    含 `ipcMain`，直接扫到 0 条通道，实际有 213 处注册。

    只认「解构里的 `ipcMain: 名字`」且右边是从 electron 拿的。
    找不到就返回空集合——不猜。
    """
    out = set()
    n = len(tokens)
    for i in range(2, n - 3):
        if tokens[i].kind != 'ident' or tokens[i].text != 'ipcMain':
            continue
        if tokens[i + 1].text != ':' or tokens[i + 2].kind != 'ident':
            continue
        # 往左找这一层解构的 `{`
        depth = 0
        open_at = None
        for j in range(i - 1, max(-1, i - 200), -1):
            text = tokens[j].text
            if text == '}':
                depth += 1
            elif text == '{':
                if depth == 0:
                    open_at = j
                    break
                depth -= 1
        if open_at is None:
            continue
        # 往右找这一层解构的 `}`，再看后面一小段有没有 electron
        depth = 0
        close_at = None
        for k in range(i + 1, min(n, i + 200)):
            text = tokens[k].text
            if text == '{':
                depth += 1
            elif text == '}':
                if depth == 0:
                    close_at = k
                    break
                depth -= 1
        if close_at is None:
            continue
        if not any(t.kind == 'string' and 'electron' in t.text
                   for t in tokens[close_at:close_at + 31]):
            continue
        out.add(tokens[i + 2].text)
    return out


def _enclosing_call(tokens, idx, start):
    """这个位置落在哪个调用的括号里：`rmSync(F.join(v, C.icon))` 里的 `C.icon`
    落在 `F.join` 的实参里。

    往回找第一个没闭合的 `(`，再看它前面是不是函数名。找不到就是 None——
    返回值不猜，只说「不在调用里」。成员调用的名字拼成 `ns.func`。
    """
    depth = 0
    for j in range(idx - 1, start - 1, -1):
        text = tokens[j].text
        if text == ')':
            depth += 1
        elif text == '(':
            if depth == 0:
                k = j - 1
                if k < 0 or tokens[k].kind != 'ident':
                    return None
                if tokens[k].text in _NOT_A_CALL:
                    return None
                name = tokens[k].text
                if k >= 2 and tokens[k - 1].text == '.' and tokens[k - 2].kind == 'ident':
                    name = tokens[k - 2].text + '.' + name
                return name
            depth -= 1
    return None


def state_writes(tokens, start, end, tainted):
    """外部值落进对象字段的地方：`C.icon = i`，以及同体内读这个字段的位置。

    这条链**跟不到下一轮**——`C` 是模块级状态，静态分析没有执行历史，
    不知道下一次 `rmSync(C.icon)` 时 C.icon 里是什么。跨请求的对象生命周期
    要堆建模 + 过程间分析，那是做不到的那层，不假装能做。

    所以两头都给出来：
      写入点：`C.icon = i` —— 外部值从哪个参数进来；
      读取点：`C.icon` 在本体里被读过的每一处 —— 人工一眼能连上「谁在用它」。

    两个都是纯静态枚举，不推演、不判断可控性。

    压缩产物的行号没有信息量（整包一行），所以位置一律给**字符偏移**。

    返回 [(字段名, 来源变量, 写入偏移, (读取偏移, ...))]。
    """
    hits = []
    limit = min(end, len(tokens) - 2)
    writes = {}
    for i in range(start, limit):
        tok = tokens[i]
        if tok.kind != 'ident':
            continue
        if i < 2 or tokens[i - 1].text != '.':
            continue
        if tokens[i + 1].text != '=':
            continue
        stop = _end_of_statement(tokens, i + 2, end)
        rhs = tokens[i + 2:stop]
        src = [t.text for t in rhs if t.kind == 'ident' and t.text in tainted]
        if src:
            writes[i] = (tok.text, src[0], tok.start)
    if not writes:
        return []
    reads = {}
    for i in range(start, limit):
        tok = tokens[i]
        if tok.kind != 'ident':
            continue
        if i < 2 or tokens[i - 1].text != '.':
            continue
        if i in writes:
            continue
        # `delete C.icon` 不是读，是清空。混在一起会让人以为有四处用到了它。
        # token 序列是 delete(ident) C(ident) . icon(ident)，所以往回数三格。
        kind = 'delete' if i >= 3 and tokens[i - 3].text == 'delete' else 'read'
        reads.setdefault(tok.text, []).append(
            (tok.start, kind, _enclosing_call(tokens, i, start)))
    out = [(field, src, off, tuple(sorted(set(reads.get(field, [])))))
           for field, src, off in writes.values()]
    out.sort(key=lambda r: (r[2], r[0]))
    return out


def _join_root(rhs):
    """`X.join(a, b, ...)` 返回第一个实参 a 的 tokens——路径拼接里 a 是根。

    返回值脏不脏，取决于根脏不脏：`F.join(v, i)` 里 v 是常量，结果被锚在 v
    底下（除非带 `..`，那要另一层判）；`F.join(i, c)` 里根本身来自外部，结果
    当然也脏。以前无条件锚定，把后一种也当成干净的了。

    只认 `.join(` / `.resolve(` 两种形状，别的内建函数一概不碰。
    根不是简单表达式（带函数调用、三元、逻辑运算）就返回 None，不锚。
    """
    if not rhs or len(rhs) < 4:
        return None
    if not (rhs[1].text == '.' and rhs[2].text in ('join', 'resolve')
            and rhs[3].text == '('):
        return None
    # 第一个实参：从 4 开始，到顶层的逗号或右括号
    first = []
    depth = 0
    for tok in rhs[4:]:
        if tok.text in ('(', '[', '{'):
            depth += 1
        elif tok.text in (')', ']', '}'):
            if depth == 0:
                break
            depth -= 1
        if tok.text == ',' and depth == 0:
            break
        first.append(tok)
    if not first:
        return None
    # 根是个简单表达式：字面量、标识符、成员链。带函数调用的不算。
    for tok in first:
        if tok.text in ('(', '?', '||', '&&'):
            return None
    return first


def assignments(tokens, start, end, params):
    """函数体里的赋值表：{名字: [右侧 token 列表, ...]}。参数也算一次赋值（值=外部）。

    **第一个参数不算外部输入。** IPC 处理函数的第一个参数是事件对象
    （`(event, payload)`），它是 Electron 塞进来的元数据，攻击者控不了。
    把它算脏会连锁传播出去：`event.sender` → 窗口 → 对话框返回值 → 路径，
    整条链在技术上成立，语义上全错。obsidian 的 `open-file` 就是这么被误报的。
    """
    live = list(params)[1:] if len(params) > 1 else list(params)
    table = {name: [None] for name in live}   # None 表示「外部来的」
    i = start
    while i < end:
        tok = tokens[i]
        name = None
        j = None
        # 解构：`const { filepath: d } = i` / `const { a } = i`。
        # 这块以前完全没接——`print-to-pdf` 里就是这么写的
        # （`let { filepath: d } = i` 然后 `writeFile(d, b)`），于是那条最严重的
        # 发现，污点引擎报的是 None。键和本地名都要认：`a: b` 取 b，`a` 取 a。
        if tok.text in DECL and i + 1 < end and tokens[i + 1].text == '{':
            close = _close_paren(tokens, i + 1)
            if close + 1 < end and tokens[close + 1].text == '=':
                stop = _end_of_statement(tokens, close + 2, end)
                rhs = tokens[close + 2:stop]
                k = i + 2
                while k < close:
                    if tokens[k].kind == 'ident':
                        after = tokens[k + 1].text if k + 1 < close else None
                        if after == ':' and k + 2 < close and tokens[k + 2].kind == 'ident':
                            table.setdefault(tokens[k + 2].text, []).append(rhs)
                            k += 3
                            continue
                        if after != ':':
                            table.setdefault(tokens[k].text, []).append(rhs)
                    k += 1
                i = max(stop, close + 2)
                continue
        if tok.text in DECL and i + 1 < end and tokens[i + 1].kind == 'ident':
            name, j = tokens[i + 1].text, i + 2
        elif tok.kind == 'ident' and i + 1 < end and tokens[i + 1].text in ASSIGN_OPS:
            # 成员赋值 `C.icon = i` 不记成局部变量 `icon = i`。
            # 那是**对象字段**，是跨语句共享的历史状态，不是本轮参数。
            # obsidian 的 `set-icon` 就是这么被误报成「rmSync 的实参外部可控」的：
            # `C.icon` 是上一次存下来的图标名，外面给不进来。
            # 字段级脏标记要对象敏感分析，这一层不做——宁可不报，不许张冠李戴。
            if i > 0 and tokens[i - 1].text == '.':
                i += 1
                continue
            name, j = tok.text, i + 1
        if name is None:
            i += 1
            continue
        if tokens[j].text != '=':
            # += 之类的复合赋值：右侧还不清楚，先记成未知
            table.setdefault(name, []).append([])
            i = j + 1
            continue
        stop = _end_of_statement(tokens, j + 1, end)
        rhs = tokens[j + 1:stop]
        # `let k = await dialog.showOpenDialog(c, { extensions: i })`：
        # 参数里的 `i` 是脏的，但**返回值不是**。函数调用的返回值和参数是两回事，
        # 混在一起会让整条链假阳性。obsidian 的 `open-file` 就是这么把
        # 「系统对话框选中的路径」报成「外部可控路径」的。
        # 只对 await 这种明确「拿返回值」的形态收手；普通调用仍然传播
        # （`String(x)` 这类确实会把脏值带过来）。
        if rhs and rhs[0].text == 'await':
            table.setdefault(name, []).append([])
        elif _join_root(rhs) is not None:
            # `let b = F.join(v, i)`：实参里有脏值，但**第一个实参是常量根**，
            # 结果被锚在 v 底下（除非后面有 `..` 逃逸，那要另一层判）。
            # 这类结果不继承脏——否则 `copy-asar` 的目标路径会被标成「外部可控」，
            # 而它其实被 join 限住了。
            table.setdefault(name, []).append(_join_root(rhs))
        else:
            table.setdefault(name, []).append(rhs)
        i = max(stop, i + 1)
    return table


def tainted_names(table, rounds=4):
    """谁身上带着外部输入。参数天生算，然后沿赋值传播，迭代到不动点。"""
    early = set()   # 这个函数不用解构那套，占位而已
    tainted = {name for name, values in table.items() if any(v is None for v in values)}
    for _ in range(rounds):
        grew = False
        for name, values in table.items():
            if name in tainted:
                continue
            for value in values:
                if value is None:
                    continue
                # 模板串是单个 token，里面出现的名字得单独捞出来——${payload.dir} 这种
                if any((tok.kind == 'ident' and tok.text in tainted)
                       or (tok.kind == 'template'
                           and any(name in tainted
                                   for name in __import__('re').findall(r'[A-Za-z_$][\w$]*', tok.text)))
                       for tok in value):
                    tainted.add(name)
                    grew = True
                    break
        if not grew:
            break
    # 解构绑出来的名字只在 early 里，得一起交出去；
    # 回调与循环带来的脏名字不在赋值表里，也要并进来
    return tainted


def child_process_aliases(tokens):
    """谁是这个文件里的 child_process：`const cp = require('child_process')`
    和 `const { exec } = require('child_process')` 两种写法都要认。

    为什么必须认：`re.exec(str)` 是正则，`cp.exec(cmd)` 才是执行命令。
    只按方法名判，会把正则全算成命令执行——这是第一版真踩到的假阳。
    """
    aliases = set()
    for i, tok in enumerate(tokens):
        if tok.text != 'require' or i + 3 >= len(tokens):
            continue
        if tokens[i + 1].text != '(' or tokens[i + 2].kind != 'string':
            continue
        if 'child_process' not in tokens[i + 2].text:
            continue
        # 往前看：const X = require(...) / const { a, b } = require(...)
        j = i - 1
        while j >= 0 and tokens[j].text not in ('=', ';', '{'):
            j -= 1
        if j >= 0 and tokens[j].text == '{':
            k = j
            while k >= 0 and tokens[k].text != '}':
                if tokens[k].kind == 'ident':
                    aliases.add(tokens[k].text)
                k -= 1
        elif j >= 1 and tokens[j].text == '=' and tokens[j - 1].kind == 'ident':
            aliases.add(tokens[j - 1].text)
    return aliases


def interprocedural_hits(tokens, defs, rounds=3):
    """跨函数补漏：调用方把脏参数传给本文件的函数，被调函数那边的形参也算脏。

    做法是迭代到不动点（最多 rounds 轮）：
      1. 每轮先按「当前已知的脏形参」重算每个函数直接碰到危险 API 的地方；
      2. 再看每个函数体里的调用点：实参里出现脏变量，就把被调函数对应位置的形参
         也标成脏；
      3. 有新脏形参就再来一轮，没有就停。

    只在本文件内传播。跨文件的（require 进来的模块）不跟——跟了就得解析模块图，
    那是另一件事；这里宁可少说，把「跨文件未分析」当成已知缺口报出来。
    """
    by_name = {item['name']: item for item in defs}
    extra = {item['name']: set() for item in defs}
    hits = {}
    for _round in range(rounds):
        hits = {}
        tainted_of = {}
        for item in defs:
            table = assignments(tokens, item['body_start'], item['body_end'], item['params'])
            for name in extra[item['name']]:
                table.setdefault(name, []).append(None)   # 外部传进来的脏
            tainted = tainted_names(table)
            tainted_of[item['name']] = tainted
            found = flows_into_danger(tokens, item['body_start'], item['body_end'],
                                      item['params'])
            if found:
                hits[item['name']] = found

        grew = False
        for item in defs:
            tainted = tainted_of[item['name']]
            for i in range(item['body_start'], min(item['body_end'], len(tokens) - 1)):
                tok = tokens[i]
                if tok.kind != 'ident' or tok.text not in by_name:
                    continue
                if tokens[i + 1].text != '(':
                    continue
                callee = by_name[tok.text]
                if callee is item:
                    continue
                stop = _end_of_statement(tokens, i + 2, item['body_end'])
                args = tokens[i + 2:stop]
                # 按位置把脏实参映射到被调函数的形参
                position, depth = 0, 0
                for token in args:
                    if token.text in '([{':
                        depth += 1
                    elif token.text in ')]}':
                        depth -= 1
                    elif token.text == ',' and depth == 0:
                        position += 1
                    elif (token.kind == 'ident' and token.text in tainted
                          and position < len(callee['params'])):
                        target = callee['params'][position]
                        if target not in extra[callee['name']]:
                            extra[callee['name']].add(target)
                            grew = True
        if not grew:
            break
    filtered = {}
    for name, found in hits.items():
        span = (by_name[name]['body_start'], by_name[name]['body_end'])
        kept = [hit for hit in found
                if not guard_neutralized(tokens, span[0], span[1], hit[1])]
        if kept:
            filtered[name] = kept
    return filtered


def guard_neutralized(tokens, start, end, name):
    """这个变量是不是先被白名单校验过、再拿去用（中和）。

    只认最保守的一种形状：`if (x !== '字面量') return;` 这类提前退出，
    且名字与字面量比较。保守的意思是——只认这一种，别的（正则、函数调用、
    白名单数组）一律不算中和，宁可多报也不替人免责。
    """
    for i in range(start, min(end, len(tokens) - 4)):
        if tokens[i].text != 'if' or tokens[i + 1].text != '(':
            continue
        close = _end_of_statement(tokens, i + 2, end)
        cond = tokens[i + 2:close]
        names = [tok.text for tok in cond if tok.kind == 'ident']
        has_literal = any(tok.kind in ('string', 'number') for tok in cond)
        compares = any(tok.text in ('!==', '!=', '===', '==') for tok in cond)
        if name in names and has_literal and compares:
            # 条件后面紧跟 return / throw，才算提前退出
            tail = tokens[min(close + 1, end - 1):min(close + 3, end)]
            if any(tok.text in ('return', 'throw') for tok in tail):
                return True
        # 函数式校验也算：if (!isSafe(payload)) return;
        if name in names:
            negated = any(tok.text == '!' for tok in cond)
            called = any(tok.kind == 'ident' and cond[k + 1].text == '('
                         for k, tok in enumerate(cond[:-1]))
            tail = tokens[min(close + 1, end - 1):min(close + 3, end)]
            if negated and called and any(tok.text in ('return', 'throw') for tok in tail):
                return True
    return False


def _group(defs):
    out = {}
    for item in defs:
        out.setdefault(item['name'], []).append(item)
    return out


def reachable_sinks(tokens, defs, roots, max_depth=4, anchors=None, with_hops=False):
    """可达性口径：从 roots 出发能调到哪些函数，其中哪些函数里有危险 API。

    和污点分析是两个问题，别混：
      可达性问「这条通道能不能碰到写文件/执行命令」——实参从哪来不重要；
      污点问「外部输入能不能到达危险参数」——那才需要看数据流。
    用污点去算可达性，会把「自己拼路径再写文件」的通道全判成 0，实测就是这样。
    """
    # 同名函数可能有好几份（压缩产物里 f/y/m/_ 都是重名的）。
    # 全跟一遍会把「附近任何一个 f 都算上」，口径立刻变宽（实测多报五十多条）。
    # 改按**离调用点最近**来挑：先找前面最近的一份，没有再找后面最近的一份。
    # 这是压缩产物能给出的最好近似——不做作用域分析，但也不会把所有同名都算。
    near = anchors.get('line') if isinstance(anchors, dict) else None
    ambiguous = {name for name, items in _group(defs).items() if len(items) > 1}
    by_name = {}
    for item in defs:
        bucket = by_name.setdefault(item['name'], [])
        bucket.append(item)
    if near is not None:
        picked = {}
        for name, items in by_name.items():
            before = [d for d in items if (d.get('line') or 0) <= near]
            after = [d for d in items if (d.get('line') or 0) > near]
            # 优先挑「身子里真有危险调用」的那一份：同类候选里它才可能是
            # 真正被调到的那个（压缩产物里同名函数常是不同模块的同名工具）。
            hot = [d for d in items if _body_has_danger(tokens, d)
                   and (d['body_end'] - d['body_start']) <= 200]
            if hot:
                chosen = hot[0]
            else:
                chosen = before[-1] if before else (after[0] if after else items[0])
            picked[name] = [chosen]
        by_name = picked
    out = {}
    hops = {}
    vias = {}
    seen, frontier, depth = set(), [(name, [name]) for name in roots], 0
    while frontier and depth < max_depth:
        nxt = []
        for name, path in frontier:
            if name in seen or name not in by_name:
                continue
            seen.add(name)
            calls, callees = [], []
            for body in by_name[name]:
                self_calls, self_callees = _scan_body(tokens, body)
                calls.extend(self_calls)
                callees.extend(self_callees)
            if calls:
                out[name] = sorted(set(calls))
                for api in calls:
                    hops.setdefault(api, depth + 1)
                    if api not in vias:
                        chain = '→'.join(path)
                        if any(item in ambiguous for item in path):
                            # 链上有个名字在包里有多份定义，这条来路只是「其中一种可能」
                            chain += '（同名多义）'
                        vias[api] = chain
            for callee in callees:
                nxt.append((callee, path + [callee]))
        frontier, depth = nxt, depth + 1
    if with_hops:
        return out, hops, vias
    return out



def _body_has_danger(tokens, body):
    """这个函数体里有没有直接的危险调用（不往下追）。"""
    for i in range(body['body_start'], min(body['body_end'], len(tokens) - 1)):
        tok = tokens[i]
        if tok.kind == 'ident' and tok.text in DANGER and tokens[i + 1].text == '(':
            if tok.text in AMBIGUOUS and i >= 2 and tokens[i - 1].text == '.':
                continue
            return True
    return False


JS_KEYWORDS = {'if', 'for', 'while', 'switch', 'catch', 'function', 'return', 'typeof',
               'new', 'delete', 'void', 'await', 'yield', 'do', 'else', 'try', 'finally',
               'in', 'of', 'instanceof', 'with', 'throw', 'case', 'default', 'var',
               'let', 'const', 'class', 'extends', 'super', 'this'}


def _scan_body(tokens, body):
    """扫一个函数体：危险调用和所有被调用的名字。"""
    calls, callees = [], []
    for i in range(body['body_start'], min(body['body_end'], len(tokens) - 1)):
        tok = tokens[i]
        if tok.kind != 'ident':
            continue
        # 成员调用 a.b(...) 也当成一条边：方法名和定义表里的方法名对上就跟。
        if (i + 3 < len(tokens) and tokens[i + 1].text in ('.', '?.')
                and tokens[i + 2].kind == 'ident' and tokens[i + 3].text == '('):
            callees.append(tokens[i + 2].text)
        if tokens[i + 1].text != '(':
            continue
        if tok.text in JS_KEYWORDS:
            # if(...)、or(...) 这种不是函数调用；早先当成调用边，
            # 于是冒出一堆「xt→if」「kt→f」的假链，把误报算到别人头上。
            continue
        callees.append(tok.text)
        if tok.text in DANGER:
            if tok.text in AMBIGUOUS and i >= 2 and tokens[i - 1].text == '.':
                continue
            calls.append(tok.text)
    return calls, callees


def _unused_old_loop():
    """占位：原来的单份循环已搬到 _scan_body，别删这段注释的来历。"""
    calls, callees = [], []
    for body in ():
        pass
    return out




def danger_aliases(tokens, start, end):
    """把危险 API 起了别名：`const i = promisify(co.exec)`、`const r = fs.readFileSync`。

    真包里这样写很常见（Obsidian 的 register-cli 就是 `promisify(co.exec)` 之后
    `await i(cmd)`）。只认「右边出现了某个危险名字」这一种形状：
    拿不准的（函数返回、动态取值）一律不认，宁可漏也不编。
    """
    out = {}
    i = start
    while i < end:
        tok = tokens[i]
        name = None
        if tok.text in DECL and i + 2 < end and tokens[i + 1].kind == 'ident':
            name, j = tokens[i + 1].text, i + 2
        elif tok.kind == 'ident' and i + 1 < end and tokens[i + 1].text == '=':
            name, j = tok.text, i + 1
        if name is None or tokens[j].text != '=':
            i += 1
            continue
        stop = _end_of_statement(tokens, j + 1, end)
        rhs = tokens[j + 1:stop]
        for k, token in enumerate(rhs):
            if token.kind == 'ident' and token.text in DANGER:
                out[name] = token.text
                break
        i = max(stop, i + 1)
    return out


def danger_at(tokens, index, limit):
    """这一串 token 是不是一次危险调用。返回 (名字, 左括号下标)，不是就 (None, None)。

    认两种写法：fs.readFileSync(...) 和 fs['readFileSync'](...)。
    后者在打包产物里很常见——按点号找会整片漏掉。
    """
    if index >= limit:
        return None, None
    tok = tokens[index]
    if tok.kind != 'ident':
        return None, None
    if tok.text in DANGER and index + 1 < limit and tokens[index + 1].text == '(':
        return tok.text, index + 1
    if (index + 4 < limit and tokens[index + 1].text == '['
            and tokens[index + 2].kind == 'string'
            and tokens[index + 3].text == ']' and tokens[index + 4].text == '('):
        name = tokens[index + 2].text.strip('\'"`')
        if name in DANGER:
            return name, index + 4
    return None, None


def sinks_in_span(tokens, start, end):
    """直接扫一段（比如内联处理函数体），看里面有没有危险调用，不看实参。"""
    aliases = danger_aliases(tokens, start, end)
    found = []
    for i in range(start, min(end, len(tokens) - 1)):
        name, _open = danger_at(tokens, i, end)
        if not name and tokens[i].kind == 'ident' and tokens[i].text in aliases \
                and i + 1 < end and tokens[i + 1].text == '(':
            name = aliases[tokens[i].text]
        if not name:
            continue
        if name in AMBIGUOUS and i >= 2 and tokens[i - 1].text == '.':
            continue
        found.append(name)
    return found


def field_key(tokens, index, limit):
    """从 index 起读一个「字段路径」：payload、payload.path、a.b.c。

    返回 (键名, 结束位置)；读不出返回 (None, index)。
    """
    if index >= limit or tokens[index].kind != 'ident':
        return None, index
    parts = [tokens[index].text]
    j = index + 1
    while j + 1 < limit and tokens[j].text in ('.', '?.') and tokens[j + 1].kind == 'ident':
        parts.append(tokens[j + 1].text)
        j += 2
    return '.'.join(parts), j


def field_taints(tokens, start, end, params):
    """带字段的脏集合：{'payload', 'payload.path'}。

    和基名版的区别就在这儿：`payload.path` 脏不等于 `payload.name` 脏。
    没有它，`if (payload.path !== '/safe') return;` 会把整条 payload 都判成干净，
    于是 `fs.read(name)` 这种真问题被中和掉。
    """
    table = {name: [None] for name in params}
    early = set(params)   # 解析阶段就能确定的脏名字，解构用得上
    i = start
    while i < end:
        tok = tokens[i]
        name = None
        j = None
        if tok.text in DECL and i + 1 < end:
            if tokens[i + 1].text in ('{', '['):
                # 解构：const { path: p } = payload / const [a, b] = payload.list
                # 右边脏就把绑出来的名字都算脏——字段级精度在这一层会让位给安全。
                close = _close_paren(tokens, i + 1)
                if close + 1 < end and tokens[close + 1].text == '=':
                    stop = _end_of_statement(tokens, close + 2, end)
                    rhs = tokens[close + 2:stop]
                    dirty = False
                    for k in range(len(rhs)):
                        key, _n = field_key(rhs, k, len(rhs))
                        if key and (key in early or key.split('.')[0] in early):
                            dirty = True
                            break
                    if dirty:
                        for k in range(i + 2, close):
                            if tokens[k].kind == 'ident':
                                early.add(tokens[k].text)
                    i = max(stop, i + 1)
                    continue
            name, j = field_key(tokens, i + 1, end)
        elif tok.kind == 'ident' and i + 1 < end and tokens[i + 1].text == '=':
            name, j = field_key(tokens, i, end)
        if name is None:
            i += 1
            continue
        if j < end and tokens[j].text == '=':
            stop = _end_of_statement(tokens, j + 1, end)
            table.setdefault(name, []).append(tokens[j + 1:stop])
            i = max(stop, i + 1)
        else:
            i = j + 1
    tainted = {name for name, values in table.items() if any(v is None for v in values)}
    for _ in range(4):
        grew = False
        for name, values in table.items():
            if name in tainted:
                continue
            for value in values:
                if value is None:
                    continue
                for k in range(len(value)):
                    key, _end = field_key(value, k, len(value))
                    if key and (key in tainted or key.split('.')[0] in tainted):
                        tainted.add(name)
                        grew = True
                        break
                    if value[k].kind == 'template' and any(
                            word in tainted or word in early
                            for word in __import__('re').findall(r'[A-Za-z_$][\w$]*',
                                                                 value[k].text)):
                        tainted.add(name)
                        grew = True
                        break
                if name in tainted:
                    break
        if not grew:
            break
    # 解构绑出来的名字只在 early 里，得一起交出去；
    # 回调与循环带来的脏名字不在赋值表里，也要并进来
    base = tainted | early
    base |= callback_taints(tokens, start, end, base)
    base |= loop_taints(tokens, start, end, base)
    base |= catch_taints(tokens, start, end, base)
    return base


def field_guarded(tokens, start, end, key):
    """这个字段是不是先被白名单校验过：`if (payload.path !== '字面量') return;`。

    按字段判，不按基名判——校验了 path 不代表 name 干净，这正是字段敏感的意义。
    """
    for i in range(start, min(end, len(tokens) - 4)):
        if tokens[i].text != 'if' or tokens[i + 1].text != '(':
            continue
        # 跳过左括号与否定号：条件可能是 `!isSafe(x)`，也可能直接 `x !== 'y'`
        start_at = i + 2
        while start_at < end and tokens[start_at].text in ('(', '!'):
            start_at += 1
        guard_key, after = field_key(tokens, start_at, end)
        if guard_key != key:
            # 字段可能是包在调用参数里的：isSafe(payload.path)
            inner = None
            for k in range(i + 2, min(end, _close_paren(tokens, i + 1))):
                if tokens[k].text == '(':
                    inner, _ = field_key(tokens, k + 1, end)
                    break
            guard_key = inner
        if guard_key != key:
            continue
        close_all = _close_paren(tokens, i + 1)
        header = tokens[i + 2:close_all]
        has_literal = any(t.kind in ('string', 'number') for t in header)
        compares = any(t.text in ('!==', '!=', '===', '==') for t in header)
        negated = any(t.text == '!' for t in header)
        called = any(t.kind == 'ident' and header[k + 1].text == '('
                     for k, t in enumerate(header[:-1]))
        tail = tokens[min(close_all + 1, end - 1):min(close_all + 3, end)]
        exits = any(t.text in ('return', 'throw') for t in tail)
        if exits and ((has_literal and compares) or (negated and called)):
            return True
    return False


def field_hits(tokens, start, end, params):
    """按字段路径判：哪个危险调用吃到了脏字段。返回 [(调用名, 字段, 行号)]。"""
    tainted = field_taints(tokens, start, end, params)
    aliases = child_process_aliases(tokens)
    hits = []
    aliases_of = danger_aliases(tokens, start, end)
    for i in range(start, min(end, len(tokens) - 1)):
        tok = tokens[i]
        name, open_at = danger_at(tokens, i, end)
        if not name and tok.kind == 'ident' and tok.text in aliases_of \
                and i + 1 < end and tokens[i + 1].text == '(':
            name, open_at = aliases_of[tok.text], i + 1
        if not name:
            continue
        if name in AMBIGUOUS and i >= 2 and tokens[i - 1].text == '.':
            if tokens[i - 2].text not in aliases:
                continue
        stop = _end_of_statement(tokens, open_at + 1, end)
        k = i + 2
        while k < stop:
            key, nxt = field_key(tokens, k, stop)
            if key and (key in tainted or key.split('.')[0] in tainted):
                if not field_guarded(tokens, start, end, key):
                    hits.append((tok.text, key, tok.line + 1))
                    break
            k = max(nxt, k + 1)
    return hits


def member_calls(tokens, start, end):
    """一段代码里的 `x.y(` 形式的成员调用，返回 [(接收者, 成员名)]。"""
    out = []
    for i in range(start, min(end, len(tokens) - 3)):
        if tokens[i].kind != 'ident' or tokens[i + 1].text not in ('.', '?.'):
            continue
        if tokens[i + 2].kind != 'ident' or tokens[i + 3].text != '(':
            continue
        out.append((tokens[i].text, tokens[i + 2].text))
    return out


def calls_name(tokens, start, end, name):
    """span 里有没有 `name(` 这种裸调用。

    只看「标识符紧跟着左括号」这一种形状。`obj.name()` 不算——那是成员调用，
    走另一条路。宁可漏，不把成员调用误算成直接调用。
    """
    limit = min(end, len(tokens) - 1)
    for i in range(start, limit):
        if tokens[i].kind == 'ident' and tokens[i].text == name:
            if tokens[i + 1].text == '(':
                return True
    return False


def cross_file_member_sinks(tokens, start, end, from_rel, files_tokens,
                            depth=2, _visited=None):
    """跨文件跟成员调用：handler 里 `svc.read(...)`，就看那个文件里的 read。

    跟 depth 层（默认两跳：main → svc → util）。每层都只认「本文件里能解析到
    包内路径」的接收者；解析不到（包名、动态 require）就停在那儿不猜。
    """
    import jsparse

    known = set(files_tokens)
    targets = cross_file_targets(tokens, from_rel, known)
    if not targets:
        return []
    visited = set() if _visited is None else _visited
    out = []
    for receiver, member in member_calls(tokens, start, end):
        for (local, imported), rel in targets.items():
            if local != receiver:
                continue
            if imported is not None and imported != member:
                continue
            other = files_tokens[rel]
            try:
                defs = jsparse.function_defs(other)
            except Exception:
                continue
            for item in defs:
                if item['name'] != member:
                    continue
                key = (rel, member)
                if key in visited:
                    continue
                visited.add(key)
                sinks = sinks_in_span(other, item['body_start'], item['body_end'])
                if sinks:
                    out.append((rel, member, sinks))
                if depth > 1:
                    out.extend(cross_file_member_sinks(
                        other, item['body_start'], item['body_end'], rel,
                        files_tokens, depth - 1, visited))

    # 跨文件的另一半：具名导入的**直接调用**。
    #   import { doSave } from './h';  doSave(p);      ← 这条以前一直是漏的
    #   const { doSave } = require('./h'); doSave(p);
    # 只认 local == imported 的那种。别名导入（import { a as b }）先不做——
    # 解不清 b 到底绑到谁就直接跳过，比猜一个错的好。
    for (local, imported), rel in targets.items():
        if imported is None or local != imported:
            continue
        if not calls_name(tokens, start, end, imported):
            continue
        other = files_tokens.get(rel)
        if other is None:
            continue
        try:
            defs = jsparse.function_defs(other)
        except Exception:
            continue
        for item in defs:
            if item['name'] != imported:
                continue
            key = (rel, imported)
            if key in visited:
                continue
            visited.add(key)
            sinks = sinks_in_span(other, item['body_start'], item['body_end'])
            if sinks:
                out.append((rel, imported, sinks))
            if depth > 1:
                out.extend(cross_file_member_sinks(
                    other, item['body_start'], item['body_end'], rel,
                    files_tokens, depth - 1, visited))
    return out

def resolve_spec(spec, from_rel, known):
    """把 require('./svc') 解析成包内的真实路径。

    spec 已经去掉引号。只处理相对路径（'./x'、'../x'）；node: / 包名一律返回 None
    ——那些不在包里，跟不过去，就老实说跟不过去。
    """
    spec = spec.strip('\'"`')
    if not spec.startswith('.'):
        return None
    base = from_rel.rsplit('/', 1)[0] if '/' in from_rel else ''
    parts = base.split('/') if base else []
    for piece in spec.split('/'):
        if piece == '.' or piece == '':
            continue
        if piece == '..':
            if parts:
                parts.pop()
            continue
        parts.append(piece)
    stem = '/'.join(parts)
    for suffix in ('', '.js', '.cjs', '.mjs', '/index.js'):
        candidate = stem + suffix
        if candidate in known:
            return candidate
    return None


def cross_file_targets(tokens, from_rel, known):
    """这个文件里，`svc.read(...)` 的 svc 指向哪个文件、导出名是什么。

    返回 {(本地别名, 导出名): 包内路径}。导出名是 None 表示整个模块对象。
    """
    out = {}
    for local, (spec, imported) in module_aliases(tokens).items():
        target = resolve_spec(spec, from_rel, known)
        if target:
            out[(local, imported)] = target
    return out


def catch_taints(tokens, start, end, tainted):
    """有界版的抛出传播：同一个 try 里抛出去的东西带外部输入，
    那它的 catch 变量也算脏。

    边界写死在这儿：只看同一层 try/catch，不跨函数、不追嵌套 try。
    超出这个范围的一律不算——宁可漏，也不编。
    """
    extra = set()
    i = start
    while i < end - 3:
        if tokens[i].text != 'try':
            i += 1
            continue
        j = i + 1
        if j >= end or tokens[j].text != '{':
            i += 1
            continue
        body_end = _close_paren(tokens, j)
        # 找 catch (NAME)
        k = body_end + 1
        if k >= end or tokens[k].text != 'catch':
            i = body_end + 1
            continue
        if k + 3 >= end or tokens[k + 1].text != '(':
            i = body_end + 1
            continue
        name = tokens[k + 2].text
        try_body = tokens[j:body_end]
        dirty = any(tok.kind == 'ident' and tok.text in tainted for tok in try_body)
        # 只有 try 里真的 throw 了才算
        if dirty and any(tok.text == 'throw' for tok in try_body):
            extra.add(name)
        i = body_end + 1
    return extra


def module_aliases(tokens):
    """这个文件里，谁指向哪个模块：`const cp = require('child_process')`、
    `import { pick } from './svc'`、`const { pick } = require('./svc')`。

    返回 {本地名: (模块说明, 导入的名字)}。跨文件跟图的第一块砖——
    没有它，`svc.pick()` 里的 svc 是什么都不知道。
    """
    aliases = {}
    for i, tok in enumerate(tokens):
        if tok.text not in ('require', 'from'):
            continue
        if tok.text == 'require':
            if i + 2 >= len(tokens) or tokens[i + 1].text != '(':
                continue
            source = tokens[i + 2] if tokens[i + 2].kind == 'string' else None
            if source is None:
                continue
            # 往前找 const X = / const { a, b } =
            j = i - 1
            while j >= 0 and tokens[j].text not in ('=', '{', ';'):
                j -= 1
            if j < 0:
                continue
            if tokens[j].text == '{':
                k = j
                while k >= 0 and tokens[k].text != '}':
                    if tokens[k].kind == 'ident':
                        aliases.setdefault(tokens[k].text, (source.text, tokens[k].text))
                    k -= 1
            elif tokens[j].text == '=' and j >= 1 and tokens[j - 1].kind == 'ident':
                aliases.setdefault(tokens[j - 1].text, (source.text, None))
            elif tokens[j].text == '=' and j >= 2 and tokens[j - 1].text == '}':
                # `const { doSave } = require('./h')`——等式左边是解构，不是单个名字。
                # 这个分支以前是漏的：`=` 前面是 `}`，走不到上面那条 ident 分支，
                # 结果整条别名都没解出来，后面的「跨文件直接调用」全跟不下去。
                depth = 0
                k = j - 1
                while k >= 0:
                    if tokens[k].text == '}':
                        depth += 1
                    elif tokens[k].text == '{':
                        depth -= 1
                        if depth == 0:
                            break
                    elif tokens[k].kind == 'ident' and depth == 1:
                        aliases.setdefault(tokens[k].text,
                                           (source.text, tokens[k].text))
                    k -= 1
            continue
        # import { a, b } from './x'  /  import X from './x'
        source = tokens[i + 1] if i + 1 < len(tokens) and tokens[i + 1].kind == 'string' else None
        if source is None:
            continue
        j = i - 1
        while j >= 0 and tokens[j].text not in ('import', ';'):
            if tokens[j].kind == 'ident':
                aliases.setdefault(tokens[j].text, (source.text, tokens[j].text))
            j -= 1
    return aliases

def _close_paren(tokens, index):
    """index 指向左括号，返回配对的右括号下标。找不到就返回末尾。"""
    depth = 0
    for i in range(index, len(tokens)):
        if tokens[i].text in ('(', '[', '{'):
            depth += 1
        elif tokens[i].text in (')', ']', '}'):
            depth -= 1
            if depth == 0:
                return i
    return len(tokens) - 1


def loop_taints(tokens, start, end, tainted):
    """循环变量也算脏：`for (const v of payload.list) { fs.read(v) }`。

    只认 for...of 一种（枚举可迭代物），不认 for...in 和 while——
    后者不保证「元素来自那个脏数组」，认了就是编。
    """
    extra = set()
    for i in range(start, min(end, len(tokens) - 4)):
        if tokens[i].text != 'for' or tokens[i + 1].text != '(':
            continue
        close = _close_paren(tokens, i + 1)
        header = tokens[i + 2:close]
        texts = [t.text for t in header]
        if 'of' not in texts:
            continue
        of_at = texts.index('of')
        # of 左边最后一个 ident 是循环变量
        names = [t for t in header[:of_at] if t.kind == 'ident']
        if not names:
            continue
        source = [t for t in header[of_at + 1:] if t.kind == 'ident']
        if source and source[0].text in tainted:
            extra.add(names[-1].text)
    return extra


def callback_taints(tokens, start, end, tainted):
    """回调里的形参也算脏：`payload.list.map(v => read(v))`。

    只在一种形状上下结论：某个脏值上调用了方法（map/forEach/filter/find/...），
    后面紧跟箭头函数，箭头形参就当脏。别的形状（回调在别处定义、传函数名）
    一律不认——认不出来就少说，不猜。
    """
    ITER = ('map', 'forEach', 'filter', 'find', 'findIndex', 'some', 'every', 'flatMap',
            'reduce', 'reduceRight')
    extra = set()
    for i in range(start, min(end, len(tokens) - 3)):
        tok = tokens[i]
        if tok.text not in ITER or tokens[i + 1].text != '(':
            continue
        # 往前走：X.map( → 看 X 是不是脏的（允许 X.y.z）
        j = i - 1
        if j >= 1 and tokens[j].text == '.':
            base = j - 1
            while base >= 1 and tokens[base - 1].text == '.':
                base -= 2
            if base < start or tokens[base].text not in tainted:
                continue
        else:
            continue
        # 往后看：map( (v) => … 或 map( v => …
        k = i + 2
        if k >= end:
            continue
        if tokens[k].text == '(':
            m = k + 1
            while m < end and tokens[m].text != ')':
                if tokens[m].kind == 'ident':
                    extra.add(tokens[m].text)
                m += 1
        elif tokens[k].kind == 'ident':
            extra.add(tokens[k].text)
    return extra


PATH_FUNCS = {'join', 'resolve', 'normalize'}


def path_taint(tokens, start, end, tainted, params=None, locals_=None, scope=None):
    """L2 一跳：脏值喂进了 `path.join` / `resolve` / `normalize`。

    为什么这层重要：`F.join(v, i)` 里 `i` 带 `..` 会跳出 `v`。零跳看不出来，
    因为危险调用收到的实参是 `F.join(...)` 的结果，不是 `i` 本身。

    **只报「喂进去了」，不判结果一定跳出去。** 能不能真跳，取决于第一个实参
    是不是常量根、以及后面有没有 `resolve` + 前缀检查——那要看内建语义，
    这一层不做。宁可报「可能」，也不给一个「确定能穿越」的假结论。

    返回 [(函数名, [脏实参], 行号)]。
    """
    hits = []
    limit = min(end, len(tokens) - 2)
    for i in range(start, limit):
        tok = tokens[i]
        if tok.kind != 'ident' or tok.text not in PATH_FUNCS:
            continue
        # 只认成员调用 path.join(...)，裸 join(...) 不知道是谁的
        if i < 2 or tokens[i - 1].text != '.':
            continue
        if tokens[i + 1].text != '(':
            continue
        close = _close_paren(tokens, i + 1)
        args = tokens[i + 2:close]
        dirty = []
        for t in args:
            if t.kind == 'ident' and t.text in tainted and t.text not in dirty:
                dirty.append(t.text)
            # 字面量里直接写 `..` 的也算——那是「确定能跳」
            elif t.kind == 'string' and '..' in t.text:
                if '..' not in dirty:
                    dirty.append('..')
        if dirty:
            # 顺着块作用域把「根到底是什么」解一层：解出字面量或已知目录，
            # 判定就能从「不知道」变成「锚定」。
            root_kind = None
            if scope is not None:
                first_args, _c = _split_args(tokens, i + 1)
                if (first_args and len(first_args[0]) == 1
                        and first_args[0][0].kind == 'ident'):
                    found = resolve_root(tokens, scope, i, first_args[0][0].text)
                    if found:
                        root_kind = classify_root(found[1])[0]
            hits.append((tok.text, dirty, tok.line,
                         join_escape_verdict(tokens, i + 1, tok.text,
                                             params=params, locals_=locals_,
                                             root_kind=root_kind)))
    return hits


def join_escape_verdict(tokens, open_at, func='join', params=None, locals_=None,
                        root_kind=None):
    """`join` / `resolve` 的调用括号下标 → 能不能真跳出根目录。

    只判三件静态事实，不推演运行时值：

      1. 第一个实参是不是**字面量常量**或者已知目录——锚点得是真的锚；
      2. 有没有 `..`——字符串字面量里的，或者拼接中单独出现的两个点；
      3. 有没有绝对路径——`/` 或 `\\` 开头，或者带盘符。

    `resolve` 和 `join` 不是一回事：`resolve('/a', '/etc')` 会跳到 `/etc`，
    `join('/a', '/etc')` 只是拼成 `/a/etc`。所以绝对路径只对 `resolve` 算逃逸。

    `root_kind` 是调用方顺着块作用域解出来的根形状（`literal` / `known-dir`），
    没有就是 None。

    根不是字面量时，再分一层「为什么不知道」：

      - `root_param`：根是这条处理函数的形参——值从外面进来，静态没有内容；
      - `root_local`：根在同体内被赋过值，但赋的不是字面量；
      - `root_unknown`：根不在这条通道看得见的作用域里。

    判不出来的一律 `root_unknown`，不往有利方向猜。
    """
    args, _close = _split_args(tokens, open_at)
    if not args:
        return 'root_unknown'
    first = args[0]
    literal_root = len(first) == 1 and first[0].kind == 'string'
    anchored_root = literal_root or root_kind in ('literal', 'known-dir')
    has_dotdot = False
    has_absolute = False
    for arg in args:
        for j, tok in enumerate(arg):
            if tok.kind == 'string':
                body = tok.text.strip('"\'`')
                if '..' in body:
                    has_dotdot = True
                if body.startswith('/') or body.startswith('\\'):
                    has_absolute = True
                elif len(body) > 1 and body[1] == ':' and body[0].isalpha():
                    has_absolute = True
            elif tok.text == '.' and j + 1 < len(arg) and arg[j + 1].text == '.':
                has_dotdot = True
    if has_dotdot:
        return 'escapes'
    if func == 'resolve' and has_absolute:
        return 'escapes'
    if anchored_root:
        return 'anchored'
    root_name = first[0].text if len(first) == 1 and first[0].kind == 'ident' else None
    if root_name and params and root_name in params:
        return 'root_param'
    if root_name and locals_ and root_name in locals_:
        return 'root_local'
    return 'root_unknown'


def _split_args(tokens, open_at):
    """把 `(` 和 `)` 之间的实参按顶层逗号切开，返回 [[token...], ...]。"""
    close = _close_paren(tokens, open_at)
    args, current, depth = [], [], 0
    for tok in tokens[open_at + 1:close]:
        if tok.text in ('(', '[', '{'):
            depth += 1
        elif tok.text in (')', ']', '}'):
            depth -= 1
        if tok.text == ',' and depth == 0:
            args.append(current)
            current = []
            continue
        current.append(tok)
    if current:
        args.append(current)
    return args, close


def _still_has_hop(tokens, start, end, defs, tainted=None):
    """这一段里还有没有「脏值能接着往下传」的下一跳。

    光看到「调用同文件函数」不够：`b()` 一个实参没给，脏值根本没进去，
    那不算被砍断。给了 `tainted` 就要求至少一个实参是脏名；
    不给就退化成「有没有调用」，只用于不知道脏值集合的场合。
    """
    names = {d['name'] for d in defs}
    if not names:
        return False
    limit = min(end, len(tokens) - 1)
    for i in range(start, limit):
        if not (tokens[i].kind == 'ident' and tokens[i].text in names
                and tokens[i + 1].text == '('):
            continue
        if tainted is None:
            return True
        try:
            args, _close = _split_args(tokens, i + 1)
        except Exception:
            return True
        for arg in args:
            if (len(arg) == 1 and arg[0].kind == 'ident'
                    and arg[0].text in tainted):
                return True
    return False


def function_summaries(tokens, defs, rounds=4):
    """函数摘要：每个函数的「副作用签名」，算一次、到处复用。

    签名分两半：

      - `sinks`：第 i 个形参能流到哪些危险调用；
      - `calls`：第 i 个形参被原样传给同文件哪个函数的第 j 个形参。

    两半都能组合：把callee 的 sinks 按形参映射拉进 caller，迭代到不动点。
    这样「深」不再靠重复遍历函数体，而是靠拼摘要——一个函数算一次，
    被十个地方调用也只算一次。

    返回 {函数体区间: {'params': [...], 'sinks': {形参名: [(api, 行号)]},
                       'calls': [(callee 区间, {形参名: 目标形参名})]}}

    只认「实参正好是形参本身」的传参（`f(x)`）。`f(x.y)`、`f(g(x))`、
    `f(x + 1)` 都不记——那要么得做表达式分析，要么会把干净的实参认成脏的。
    """
    by_key = {}
    for d in defs:
        key = (d['body_start'], d['body_end'])
        by_key.setdefault(key, d)
    by_name = {}
    for d in defs:
        by_name.setdefault(d['name'], (d['body_start'], d['body_end']))

    summaries = {}
    for key, d in by_key.items():
        params = list(d.get('params') or [])
        if not params:
            summaries[key] = {'params': [], 'sinks': {}, 'calls': []}
            continue
        sinks = {}
        calls = []
        try:
            flows = flows_into_danger(tokens, key[0], key[1], params)
        except Exception:
            flows = []
        for api, arg, line, _shape in flows:
            if arg in params:
                sinks.setdefault(arg, []).append((api, line))
        limit = min(key[1], len(tokens) - 1)
        for i in range(key[0], limit - 1):
            if tokens[i].kind != 'ident' or tokens[i + 1].text != '(':
                continue
            callee = by_name.get(tokens[i].text)
            if not callee or callee == key:
                continue
            try:
                args, _close = _split_args(tokens, i + 1)
            except Exception:
                continue
            callee_params = list(by_key[callee].get('params') or [])
            mapping = {}
            for pos, arg in enumerate(args):
                if pos >= len(callee_params):
                    break
                if len(arg) == 1 and arg[0].kind == 'ident' and arg[0].text in params:
                    mapping[arg[0].text] = callee_params[pos]
            if mapping:
                calls.append((callee, mapping))
        summaries[key] = {'params': params, 'sinks': sinks, 'calls': calls}

    # 摘要组合：把 callee 的 sinks 按形参映射拉进 caller，跑到不动点。
    # 轮数封顶，环状调用图不会死循环；每轮只做集合合并，不再遍历函数体。
    for _round in range(rounds):
        changed = False
        for key, summary in summaries.items():
            for callee, mapping in summary['calls']:
                target = summaries.get(callee)
                if not target:
                    continue
                for src_param, dst_param in mapping.items():
                    for api, line in target['sinks'].get(dst_param) or []:
                        bucket = summary['sinks'].setdefault(src_param, [])
                        if (api, line) not in bucket:
                            bucket.append((api, line))
                            changed = True
        if not changed:
            break
    return summaries


def summary_sinks(summaries, func_key, tainted_params):
    """拿函数摘要回答「这些脏形参会碰到什么」，不重新遍历函数体。"""
    summary = summaries.get(func_key)
    if not summary:
        return []
    hits = []
    for param in tainted_params:
        for api, line in summary['sinks'].get(param) or []:
            hits.append((api, param, line))
    return hits


def interproc_taint_via_summaries(tokens, start, end, tainted, defs, summaries):
    """和 `interproc_taint` 同样的活，但查摘要，不递归遍历函数体。

    `interproc_taint` 每遇到一个调用就把被调函数的体重新扫一遍；同一个函数被
    二十个 handler 调用，就扫二十遍。这里换一下：摘要已经算过一次，
    调用点只做「形参映射 + 查表」。

    深度不再是参数——摘要组合已经在 `function_summaries` 里跑到不动点，
    四层调用链和两层一样是一次查表。

    返回 [(被调函数名, 危险 API, 形参, 行号)]，形状和 `interproc_taint` 一致。
    """
    by_name = {}
    for d in defs:
        by_name.setdefault(d['name'], d)
    hits = []
    limit = min(end, len(tokens) - 1)
    for i in range(start, limit):
        if tokens[i].kind != 'ident' or tokens[i + 1].text != '(':
            continue
        target = by_name.get(tokens[i].text)
        if target is None:
            continue
        try:
            args, _close = _split_args(tokens, i + 1)
        except Exception:
            continue
        fparams = list(target.get('params') or [])
        dirty_params = []
        for pos, arg in enumerate(args):
            if pos >= len(fparams):
                break
            if len(arg) == 1 and arg[0].kind == 'ident' and arg[0].text in tainted:
                dirty_params.append(fparams[pos])
        if not dirty_params:
            continue
        key = (target['body_start'], target['body_end'])
        for api, param, line in summary_sinks(summaries, key, dirty_params):
            hits.append((tokens[i].text, api, param, line))
    return hits


def interproc_taint(tokens, start, end, tainted, defs, depth=2, _seen=None,
                    _truncated=None, _cache=None):
    """L3：脏实参传进本文件里另一个函数，跟进去看它能不能到危险参数。

    只跟两种被调者：本文件里有 `function name()` 声明的、或 `const name = ...`
    这类能认出名字的。认不出名字的调用（`obj.m()`、`factory()` 返回值）一律跳过
    ——跟不到就停，不猜。

    形参和实参按**位置**对齐。实参不是裸名字（比如 `a.b`、`f(x)`）的位置，
    对应形参不标脏：那需要更细的表达式分析，这层不做。

    返回 [(被调函数名, 危险 API, 脏形参, 行号)]。
    """
    if depth <= 0:
        return []
    seen = set() if _seen is None else _seen
    by_name = {}
    for d in defs:
        by_name.setdefault(d['name'], d)
    hits = []
    limit = min(end, len(tokens) - 1)
    for i in range(start, limit):
        tok = tokens[i]
        if tok.kind != 'ident' or tokens[i + 1].text != '(':
            continue
        target = by_name.get(tok.text)
        if target is None:
            continue
        key = (target['body_start'], target['body_end'])
        if key in seen:
            continue
        args, close = _split_args(tokens, i + 1)
        fparams = list(target.get('params') or [])
        dirty_params = []
        for pos, arg in enumerate(args):
            if pos >= len(fparams):
                break
            if len(arg) == 1 and arg[0].kind == 'ident' and arg[0].text in tainted:
                dirty_params.append(fparams[pos])
        if not dirty_params:
            continue
        seen.add(key)
        # 函数体分析结果按区间缓存：同一个函数被二十个 handler 调用时，
        # `flows_into_danger` 只跑一次。这就是摘要的收益，但不用预先把
        # 全文件的函数都算一遍——那批包上实测是负优化（0.3 秒变 8.4 秒）。
        if _cache is not None and key in _cache:
            inner = _cache[key]
        else:
            inner = flows_into_danger(tokens, target['body_start'], target['body_end'],
                                      dirty_params)
            if _cache is not None:
                _cache[key] = inner
        for api, arg, line, _shape in inner:
            hits.append((tok.text, api, arg, line))
        if depth > 1:
            hits.extend(
                (name, api, arg, ln2)
                for name, api, arg, ln2 in interproc_taint(
                    tokens, target['body_start'], target['body_end'],
                    set(dirty_params), defs, depth - 1, seen, _truncated, _cache)
            )
        elif _truncated is not None:
            # 不往下走了。如果这个函数体里还有「调用同文件函数」的下一跳，
            # 那就是被深度上限砍断的一跳——记下来，别当成「到头了」。
            if _still_has_hop(tokens, target['body_start'], target['body_end'],
                              defs, set(dirty_params)):
                _truncated.append((target['body_start'], target['body_end']))
    return hits


def flows_into_danger(tokens, start, end, params, aliases=None):
    """函数体里，哪个危险调用吃到了外部输入。返回 [(调用名, 参数名, 行号)]。"""
    table = assignments(tokens, start, end, params)
    tainted = tainted_names(table)
    tainted |= callback_taints(tokens, start, end, tainted)
    tainted |= loop_taints(tokens, start, end, tainted)
    tainted |= catch_taints(tokens, start, end, tainted)
    aliases = aliases if aliases is not None else child_process_aliases(tokens)
    # 立即执行的匿名函数：(function (p) { fs.read(p) })(payload.path)
    # 实参脏就把形参也算脏，否则这种写法整片漏掉。
    for i in range(start, min(end, len(tokens) - 1)):
        if tokens[i].text != 'function' or i < 1 or tokens[i - 1].text != '(':
            continue
        if tokens[i + 1].text != '(':
            continue
        p_open = i + 1
        p_close = _close_paren(tokens, p_open)
        if p_close + 1 >= end or tokens[p_close + 1].text != '{':
            continue
        b_close = _close_paren(tokens, p_close + 1)
        if (b_close + 2 >= end or tokens[b_close + 1].text != ')'
                or tokens[b_close + 2].text != '('):
            continue
        arg_end = _end_of_statement(tokens, b_close + 3, end)
        args = tokens[b_close + 3:arg_end]
        if any(a.kind == 'ident' and a.text in tainted for a in args):
            for tok in tokens[p_open + 1:p_close]:
                if tok.kind == 'ident':
                    tainted.add(tok.text)
    hits = []
    for i in range(start, min(end, len(tokens) - 1)):
        tok = tokens[i]
        name, open_at = danger_at(tokens, i, end)
        if not name:
            continue
        # 成员调用要认接收者：cp.exec(cmd) 算，re.exec(s) 不算
        if name in AMBIGUOUS and i >= 2 and tokens[i - 1].text == '.':
            if tokens[i - 2].text not in aliases:
                continue
        # 实参要扫到右括号为止。用 `_end_of_statement` 是错的——它在逗号处
        # 就停了（那是判语句结尾用的），于是 `renameSync(i, c)` 只扫到 `i`。
        # 而真正要修的是 `c`（目标路径零校验）。
        # 每个脏实参都要记，不能找到一个就走：两个都来自外部就两个都写出来。
        stop = _close_paren(tokens, open_at)
        arg_lists, _ignored = _split_args(tokens, open_at)
        seen_here = set()
        for other in tokens[open_at + 1:stop]:
            if (other.kind == 'ident' and other.text in tainted
                    and other.text not in seen_here):
                seen_here.add(other.text)
                # 「有多直接」：这个实参整个就是那个变量，还是它被包在一层
                # 表达式里（`String(i)`、`i.trim()`、`v + i`）。前者是原样
                # 交出去的，后者中间还有别的东西在动它。
                shape = 'direct'
                for arg in arg_lists:
                    if any(t is other for t in arg):
                        if len(arg) != 1:
                            shape = 'wrapped'
                        break
                hits.append((name, other.text, tok.line + 1, shape))
    return hits

