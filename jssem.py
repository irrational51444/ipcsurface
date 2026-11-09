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
                if any(tok.kind == 'ident' and tok.text in tainted for tok in value):
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
    return hits

def flows_into_danger(tokens, start, end, params, aliases=None):
    """函数体里，哪个危险调用吃到了外部输入。返回 [(调用名, 参数名, 行号)]。"""

    """函数体里，哪个危险调用吃到了外部输入。返回 [(调用名, 参数名, 行号)]。"""
    table = assignments(tokens, start, end, params)
    tainted = tainted_names(table)
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

