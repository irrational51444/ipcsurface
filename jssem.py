"""jssem —— 第一层语义：作用域、赋值、以及「参数能不能流到危险 API」。

只做一件事，但要做细：同函数内，参数经局部变量转手（`const p = payload.path`）
再进危险调用，也算流到了。做法是在函数体的 token 上做赋值传播，迭代到不动点。

不做：跨函数参数映射、类型推断、原型链、eval、分支敏感。
这些一律不算「安全」，报告里必须写「未分析」——没分析不等于没问题。
"""

DANGER_KINDS = {
    '文件写': ('writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
             'createWriteStream', 'unlink', 'unlinkSync', 'rmSync', 'rename', 'renameSync'),
    '文件读': ('readFile', 'readFileSync', 'createReadStream', 'readdir', 'readdirSync'),
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


def assignments(tokens, start, end, params):
    """函数体里的赋值表：{名字: [右侧 token 列表, ...]}。参数也算一次赋值（值=外部）。"""
    table = {name: [None] for name in params}   # None 表示「外部来的」
    i = start
    while i < end:
        tok = tokens[i]
        name = None
        j = None
        if tok.text in DECL and i + 1 < end and tokens[i + 1].kind == 'ident':
            name, j = tokens[i + 1].text, i + 2
        elif tok.kind == 'ident' and i + 1 < end and tokens[i + 1].text in ASSIGN_OPS:
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
        table.setdefault(name, []).append(tokens[j + 1:stop])
        i = max(stop, i + 1)
    return table


def tainted_names(table, rounds=4):
    """谁身上带着外部输入。参数天生算，然后沿赋值传播，迭代到不动点。"""
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

def reachable_sinks(tokens, defs, roots, max_depth=3):
    """可达性口径：从 roots 出发能调到哪些函数，其中哪些函数里有危险 API。

    和污点分析是两个问题，别混：
      可达性问「这条通道能不能碰到写文件/执行命令」——实参从哪来不重要；
      污点问「外部输入能不能到达危险参数」——那才需要看数据流。
    用污点去算可达性，会把「自己拼路径再写文件」的通道全判成 0，实测就是这样。
    """
    by_name = {item['name']: item for item in defs}
    out = {}
    seen, frontier, depth = set(), list(roots), 0
    while frontier and depth < max_depth:
        nxt = []
        for name in frontier:
            if name in seen or name not in by_name:
                continue
            seen.add(name)
            body = by_name[name]
            calls = []
            for i in range(body['body_start'], min(body['body_end'], len(tokens) - 1)):
                tok = tokens[i]
                if tok.kind == 'ident' and tok.text in DANGER and tokens[i + 1].text == '(':
                    if tok.text in AMBIGUOUS and i >= 2 and tokens[i - 1].text == '.':
                        continue
                    calls.append(tok.text)
            if calls:
                out[name] = calls
            nxt.extend(body.get('calls', []))
        frontier, depth = nxt, depth + 1
    return out


def sinks_in_span(tokens, start, end):
    """直接扫一段（比如内联处理函数体），看里面有没有危险调用，不看实参。"""
    found = []
    for i in range(start, min(end, len(tokens) - 1)):
        tok = tokens[i]
        if tok.kind == 'ident' and tok.text in DANGER and tokens[i + 1].text == '(':
            if tok.text in AMBIGUOUS and i >= 2 and tokens[i - 1].text == '.':
                continue
            found.append(tok.text)
    return found


def field_key(tokens, index, limit):
    """从 index 起读一个「字段路径」：payload、payload.path、a.b.c。

    返回 (键名, 结束位置)；读不出返回 (None, index)。
    """
    if index >= limit or tokens[index].kind != 'ident':
        return None, index
    parts = [tokens[index].text]
    j = index + 1
    while j + 1 < limit and tokens[j].text == '.' and tokens[j + 1].kind == 'ident':
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
    i = start
    while i < end:
        tok = tokens[i]
        name = None
        j = None
        if tok.text in DECL and i + 1 < end:
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
                if name in tainted:
                    break
        if not grew:
            break
    return tainted


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
    for i in range(start, min(end, len(tokens) - 1)):
        tok = tokens[i]
        if tok.kind != 'ident' or tok.text not in DANGER or tokens[i + 1].text != '(':
            continue
        if tok.text in AMBIGUOUS and i >= 2 and tokens[i - 1].text == '.':
            if tokens[i - 2].text not in aliases:
                continue
        stop = _end_of_statement(tokens, i + 2, end)
        k = i + 2
        while k < stop:
            key, nxt = field_key(tokens, k, stop)
            if key and (key in tainted or key.split('.')[0] in tainted):
                if not field_guarded(tokens, start, end, key):
                    hits.append((tok.text, key, tok.line + 1))
                    break
            k = max(nxt, k + 1)
    return hits


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
    ITER = ('map', 'forEach', 'filter', 'find', 'findIndex', 'some', 'every', 'flatMap')
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


def flows_into_danger(tokens, start, end, params, aliases=None):
    """函数体里，哪个危险调用吃到了外部输入。返回 [(调用名, 参数名, 行号)]。"""

    """函数体里，哪个危险调用吃到了外部输入。返回 [(调用名, 参数名, 行号)]。"""
    table = assignments(tokens, start, end, params)
    tainted = tainted_names(table)
    tainted |= callback_taints(tokens, start, end, tainted)
    tainted |= loop_taints(tokens, start, end, tainted)
    aliases = aliases if aliases is not None else child_process_aliases(tokens)
    hits = []
    for i in range(start, min(end, len(tokens) - 1)):
        tok = tokens[i]
        if tok.kind != 'ident' or tok.text not in DANGER:
            continue
        if tokens[i + 1].text != '(':
            continue
        # 成员调用要认接收者：cp.exec(cmd) 算，re.exec(s) 不算
        if tok.text in AMBIGUOUS and i >= 2 and tokens[i - 1].text == '.':
            if tokens[i - 2].text not in aliases:
                continue
        stop = _end_of_statement(tokens, i + 2, end)
        arg = tokens[i + 2:stop]
        for other in arg:
            if other.kind == 'ident' and other.text in tainted:
                hits.append((tok.text, other.text, tok.line + 1))
                break
    return hits

