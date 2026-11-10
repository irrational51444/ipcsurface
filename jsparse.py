"""jsparse —— 够用的 JS 词法与结构扫描，不追求完整语法树。

为什么要自己写：正则看不出「这个括号在字符串里」「这段是注释」「这是对象方法
简写还是调用」。词法做对之后，括号配对才可信，函数定义和调用才数得准。

范围（有意窄）：
- 词法：标识符、数字、字符串、模板串（含 ${} 嵌套）、注释、标点、正则（保守）
- 结构：找函数定义（function / 箭头 / 对象方法简写），记下它的体在哪、调了什么
- 明确不做：表达式求值、作用域、类型、ASI 细节

解析失败一律抛 ParseError，由调用方记成 unknown——不猜。
"""

import re

IDENT_START = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$')
IDENT_PART = IDENT_START | set('0123456789')
PUNCT = list('{}()[];,<>+-*/%&|^!~?:=.@#')
# 多字符运算符必须先试长的，否则 !== 会被拆成 ! = = 三个 token，
# 上层任何「比较符」判定都会失效（中性化判定就栽在这上面）。
OPS = ('>>>=', '...', '===', '!==', '**=', '<<=', '>>=', '=>', '==', '!=', '<=', '>=',
       '&&', '||', '++', '--', '+=', '-=', '*=', '/=', '??', '?.', '<<', '>>', '**')
NUMBER_RE = re.compile(r'[0-9][0-9a-zA-Z_.]*')
REGEX_PREV = set('(,=:[!&|?{};+-*%<>~^')


class ParseError(Exception):
    """词法或结构上过不去。调用方该把它记成 unknown，而不是猜一个结果。"""


class Token:
    __slots__ = ('kind', 'text', 'line', 'start', 'end')

    def __init__(self, kind, text, line, start, end):
        self.kind = kind      # ident / number / string / template / punct / comment / regex
        self.text = text
        self.line = line
        self.start = start
        self.end = end

    def __repr__(self):
        return f'Token({self.kind!r}, {self.text[:12]!r}, line={self.line})'


def tokenize(text):
    """把源码切成 token。注释丢掉，但保留它们占的位置（行号才对得上）。"""
    tokens = []
    i, line = 0, 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '\n':
            line += 1
            i += 1
            continue
        if ch in ' \t\r':
            i += 1
            continue
        if text.startswith('//', i):
            end = text.find('\n', i)
            i = n if end == -1 else end
            continue
        if text.startswith('/*', i):
            end = text.find('*/', i + 2)
            if end == -1:
                raise ParseError('注释没有结尾')
            line += text.count('\n', i, end)
            i = end + 2
            continue
        if ch in '\'"':
            start, start_line = i, line
            i += 1
            while i < n:
                if text[i] == '\\':
                    i += 2
                    continue
                if text[i] == ch:
                    i += 1
                    break
                if text[i] == '\n':
                    # 真包的打包产物里会出现这种：引号落单，字符串跨到下一行。
                    # 整份文件因为一个字放弃不值得——就在这里断开，后面照常扫。
                    break
                i += 1
            else:
                raise ParseError('字符串没有结尾')
            tokens.append(Token('string', text[start:i], start_line, start, i))
            continue
        if ch == '`':
            start, start_line = i, line
            depth = 0
            i += 1
            while i < n:
                if text[i] == '\\':
                    i += 2
                    continue
                if text.startswith('${', i):
                    depth += 1
                    i += 2
                    continue
                if text[i] == '}' and depth:
                    depth -= 1
                    i += 1
                    continue
                if text[i] == '`' and depth == 0:
                    i += 1
                    break
                if text[i] == '\n':
                    line += 1
                i += 1
            else:
                raise ParseError('模板串没有结尾')
            tokens.append(Token('template', text[start:i], start_line, start, i))
            continue
        if ch in IDENT_START:
            start = i
            while i < n and text[i] in IDENT_PART:
                i += 1
            tokens.append(Token('ident', text[start:i], line, start, i))
            continue
        if ch.isdigit():
            match = NUMBER_RE.match(text, i)
            tokens.append(Token('number', match.group(0), line, i, match.end()))
            i = match.end()
            continue
        if ch == '/' and i + 1 < n and _regex_allowed(tokens):
            start = i
            i += 1
            in_class = False
            while i < n:
                if text[i] == '\\':
                    i += 2
                    continue
                if text[i] == '[':
                    in_class = True
                elif text[i] == ']':
                    in_class = False
                elif text[i] == '/' and not in_class:
                    i += 1
                    break
                elif text[i] == '\n':
                    raise ParseError('正则没有结尾')
                i += 1
            while i < n and text[i] in IDENT_PART:
                i += 1
            tokens.append(Token('regex', text[start:i], line, start, i))
            continue
        merged = next((op for op in OPS if text.startswith(op, i)), None)
        if merged:
            tokens.append(Token('punct', merged, line, i, i + len(merged)))
            i += len(merged)
            continue
        if ch in PUNCT:
            tokens.append(Token('punct', ch, line, i, i + 1))
            i += 1
            continue
        # 真包里会出现落单的反斜杠（续行、正则被误判成正则之外的位置等）。
        # 它不可能变成标识符，当成标点收下比整份文件解析失败更有用；
        # 记成 punct，谁也不会把它当名字用。
        if ch == '\\':
            tokens.append(Token('punct', '\\', line, i, i + 1))
            i += 1
            continue
        raise ParseError(f'没见过的字符 {ch!r}（第 {line + 1} 行、第 {i - text.rfind(chr(10), 0, i)} 列）')
    return tokens


def _regex_allowed(tokens):
    """斜杠是除号还是正则开头：看前一个有效 token。这是 JS 里的老难题，
    这里只做保守判断——判错就抛 ParseError，不猜。"""
    if not tokens:
        return True
    prev = tokens[-1]
    if prev.kind in ('ident', 'number', 'string', 'template', 'regex'):
        return prev.text in ('return', 'typeof', 'case', 'in', 'of', 'delete', 'void')
    return prev.text in REGEX_PREV


def match_brace(tokens, index):
    """tokens[index] 是 { 或 ( 或 [，返回配对的右括号下标。"""
    pairs = {'{': '}', '(': ')', '[': ']'}
    opening = tokens[index].text
    closing = pairs.get(opening)
    if closing is None:
        raise ParseError(f'{opening} 不是开括号')
    depth = 0
    for i in range(index, len(tokens)):
        text = tokens[i].text
        if text == opening:
            depth += 1
        elif text == closing:
            depth -= 1
            if depth == 0:
                return i
    raise ParseError(f'{opening} 没有配对')


def object_property_functions(tokens):
    """对象属性形式的函数：`pick: (p) => { … }`、`pick: function (p) { … }`。

    打包产物里这比方法简写更常见，只认简写会漏掉一大片——真包 41 条通道
    只能走到 1 条，主要就是栽在这儿。
    """
    found = []
    for i, tok in enumerate(tokens):
        if tok.kind != 'ident' or i + 2 >= len(tokens) or tokens[i + 1].text != ':':
            continue
        j = i + 2
        # pick: function (p) { … }
        if tokens[j].text == 'function':
            k = j + 1
            if k < len(tokens) and tokens[k].text == '(':
                close = match_brace(tokens, k)
                if close + 1 < len(tokens) and tokens[close + 1].text == '{':
                    end = match_brace(tokens, close + 1)
                    found.append({'name': tok.text, 'line': tok.line,
                                  'params': _param_names(tokens, k, close),
                                  'body_start': close + 1, 'body_end': end})
            continue
        # pick: (p) => { … }   /   pick: p => …
        params, arrow = [], None
        if tokens[j].text == '(':
            close = match_brace(tokens, j)
            params = _param_names(tokens, j, close)
            arrow = close + 1
        elif tokens[j].kind == 'ident':
            params = [tokens[j].text]
            arrow = j + 1
        if arrow is None or arrow >= len(tokens):
            continue
        if tokens[arrow].text == '=>':
            body = arrow + 1
        elif (arrow + 1 < len(tokens) and tokens[arrow].text == '='
              and tokens[arrow + 1].text == '>'):
            body = arrow + 2
        else:
            continue
        if body < len(tokens) and tokens[body].text == '{':
            end = match_brace(tokens, body)
        else:
            end = _expression_end(tokens, body)
        found.append({'name': tok.text, 'line': tok.line, 'params': params,
                      'body_start': body, 'body_end': end})
    return found


def function_defs(tokens):
    """找函数定义：function f()、const f = () =>、对象方法简写 f() {。

    返回 [{name, params, line, body_start, body_end}]，body_* 是 tokens 下标。
    认不出名字的定义（匿名回调）跳过——它们在调用图里没有节点。
    """
    found = object_property_functions(tokens)
    for i, tok in enumerate(tokens):
        if tok.kind != 'ident':
            continue
        # function 名字 (…) {
        if tok.text == 'function':
            name = tokens[i + 1].text if i + 1 < len(tokens) and tokens[i + 1].kind == 'ident' else None
            j = i + 1 if name is None else i + 2
            if name is None or j >= len(tokens) or tokens[j].text != '(':
                continue
            close = match_brace(tokens, j)
            if close + 1 < len(tokens) and tokens[close + 1].text == '{':
                end = match_brace(tokens, close + 1)
                found.append({'name': name, 'line': tok.line, 'params': _param_names(tokens, j, close),
                              'body_start': close + 1, 'body_end': end})
            continue
        # 对象方法简写：ident (…) {
        if i + 1 < len(tokens) and tokens[i + 1].text == '(':
            if i > 0 and tokens[i - 1].text in ('{', ','):
                close = match_brace(tokens, i + 1)
                if close + 1 < len(tokens) and tokens[close + 1].text == '{':
                    end = match_brace(tokens, close + 1)
                    found.append({'name': tok.text, 'line': tok.line,
                                  'params': _param_names(tokens, i + 1, close),
                                  'body_start': close + 1, 'body_end': end})
    # 箭头函数：const f = (…) => …（只认块体或单表达式）
    for i, tok in enumerate(tokens):
        if tok.kind != 'ident' or i + 1 >= len(tokens):
            continue
        if tokens[i + 1].text != '=' or (i + 2 < len(tokens) and tokens[i + 2].text == '='):
            continue
        j = i + 2
        if j < len(tokens) and tokens[j].text == '=' and j + 1 < len(tokens) and tokens[j + 1].text == '>':
            pass
        params = []
        if j < len(tokens) and tokens[j].text == '(':
            close = match_brace(tokens, j)
            params = _param_names(tokens, j, close)
            arrow = close + 1
        elif j < len(tokens) and tokens[j].kind == 'ident':
            params = [tokens[j].text]
            arrow = j + 1
        else:
            continue
        if tokens[arrow].text == '=>':
            body = arrow + 1
        elif (arrow + 1 < len(tokens) and tokens[arrow].text == '='
              and tokens[arrow + 1].text == '>'):
            body = arrow + 2
        else:
            continue
        if body < len(tokens) and tokens[body].text == '{':
            end = match_brace(tokens, body)
        else:
            end = _expression_end(tokens, body)
        found.append({'name': tok.text, 'line': tok.line, 'params': params,
                      'body_start': body, 'body_end': end})
    return found


def _param_names(tokens, open_paren, close_paren):
    names, expect = [], False
    for token in tokens[open_paren + 1:close_paren]:
        if token.kind == 'ident' and (expect or token is tokens[open_paren + 1]):
            names.append(token.text)
            expect = False
        elif token.text == ',':
            expect = True
        elif token.text in ('{', '[', '='):
            expect = False
    return names


def _expression_end(tokens, index):
    """单表达式体的结束位置：遇到顶层 , 或 ) 或 ; 就停。"""
    depth = 0
    for i in range(index, len(tokens)):
        text = tokens[i].text
        if text in '([{':
            depth += 1
        elif text in ')]}':
            if depth == 0:
                return i - 1
            depth -= 1
        elif text in ',;' and depth == 0:
            return i - 1
    return len(tokens) - 1


def calls_in(tokens, start, end):
    """[start, end] 里出现的调用名（ident 后面紧跟左括号），按出现顺序去重。"""
    seen = []
    for i in range(start, min(end, len(tokens) - 1) + 1):
        token = tokens[i]
        if token.kind != 'ident':
            continue
        if i + 1 <= end and tokens[i + 1].text == '(':
            if token.text not in seen:
                seen.append(token.text)
    return seen


def analyse(text):
    """一步到位：源码 → {函数名: {line, params, calls}}。

    词法或结构上任何一处过不去都抛 ParseError；调用方记 unknown。
    """
    tokens = tokenize(text)
    defs = function_defs(tokens)
    out = {}
    for item in defs:
        calls = calls_in(tokens, item['body_start'], item['body_end'])
        out.setdefault(item['name'], {
            'line': item['line'] + 1,
            'params': item['params'],
            'calls': calls,
        })
    return out


def _string_of(token):
    """把一个字符串字面量的内容取出来（去掉引号，处理常见转义）。"""
    if token.kind not in ('string', 'template'):
        return None
    body = token.text[1:-1]
    return body.encode('utf-8').decode('unicode_escape') if '\\' in body else body



def unattributed_registrations(tokens, objects=None):
    """数一数「注册了但名字不是字面量、我也解不出来」的注册点。

    这不算失败，是个必须报出来的空档：抖音桌面端就是这样，
    `ipcMain.handle(x.channel, …)` 的名字在运行时才成形，静态拿不到。
    有数字，读报告的人才知道「41 条」是全部还是残的。
    """
    count = 0
    for i, tok in enumerate(tokens):
        if tok.text not in ('handle', 'handleOnce', 'on', 'once', 'send', 'invoke'):
            continue
        if i < 2 or tokens[i - 1].text not in ('.', '?.'):
            continue
        if tokens[i - 2].text not in ('ipcMain', 'ipcRenderer', 'webContents'):
            continue
        if i + 2 >= len(tokens) or tokens[i + 1].text != '(':
            continue
        first = tokens[i + 2]
        if first.kind == 'string':
            continue
        # obj.KEY 这种能从常量对象表解出来的，不算归不到
        resolved = False
        if first.kind == 'ident' and i + 4 < len(tokens) and tokens[i + 3].text in ('.', '?.'):
            owner, key = first.text, tokens[i + 4].text
            if objects and key in (objects.get(owner) or {}):
                resolved = True
        if not resolved:
            count += 1
    return count


def ipc_registrations(tokens, objects=None):
    """找 ipcMain.handle / on / handleOnce 的注册点。

    返回 [{channel, target, calls, line}]：
      channel —— 第一个实参是字符串字面量时的值；不是就是 None（名字是算的）
      target  —— 第二个实参是标识符时的函数名（handler 引用已有函数）
      calls   —— 内联函数体里直接出现的调用名
    """
    found = []
    for i, token in enumerate(tokens):
        if token.kind != 'ident' or token.text not in ('ipcMain', 'ipcRenderer'):
            continue
        j = i + 1
        method = None
        if j < len(tokens) and tokens[j].text == '.' and j + 1 < len(tokens):
            method = tokens[j + 1].text
            j += 2
        elif j < len(tokens) and tokens[j].text == '[':
            close = match_brace(tokens, j)
            inner = tokens[j + 1:close]
            if len(inner) == 1 and inner[0].kind == 'string':
                method = _string_of(inner[0])
            j = close + 1
        if method not in ('handle', 'handleOnce', 'on', 'invoke', 'send', 'sendSync'):
            continue
        if j >= len(tokens) or tokens[j].text != '(':
            continue
        close = match_brace(tokens, j)
        args = _split_args(tokens, j + 1, close)
        if not args:
            continue
        first = args[0]
        channel = None
        if len(first) == 1 and first[0].kind in ('string', 'template'):
            channel = _string_of(first[0])
        elif len(first) == 3 and first[0].kind == 'ident' and first[1].text == '.':
            # 常量对象成员：DESKTOP_IPC.fileSave。表由调用方喂进来，解不出就是 None
            channel = (objects or {}).get(first[0].text, {}).get(first[2].text)
        target, calls, guards = None, [], []
        if len(args) >= 2:
            second = args[1]
            if len(second) == 1 and second[0].kind == 'ident':
                target = second[0].text
            else:
                start_i = tokens.index(second[0]) if second else 0
                start = second[0].start if second else 0
                end_i = tokens.index(second[-1]) + 1 if second else 0
                end = second[-1].end if second else 0
                calls = [tok.text for k, tok in enumerate(tokens)
                         if tok.start >= start and tok.end <= end
                         and tok.kind == 'ident' and k + 1 < len(tokens)
                         and tokens[k + 1].text == '(']
        span = None
        if len(args) >= 2 and args[1]:
            span = (tokens.index(args[1][0]), tokens.index(args[1][-1]))
        found.append({'channel': channel, 'target': target, 'span': span,
                      'calls': list(dict.fromkeys(calls)),
                      'guards': list(dict.fromkeys(guards)), '_window': [t.text for t in tokens[start_i:end_i]], 'line': token.line + 1})
    # 来源校验常常写成内联比较（event.sender !== window.webContents），
    # 只按被调函数名找会把它漏成「没有校验」。这里按 token 兜一遍。
    GUARD_NAME = ('assert', 'check', 'validate', 'verify', 'ensure', 'require')
    for item in found:
        for name in item['calls']:
            if name.lower().startswith(GUARD_NAME):
                item['guards'].append('call:' + name)
        window = item.pop('_window', [])
        if any(name in window for name in
               ('sender', 'senderFrame', 'getURL', 'webContents')):
            item['guards'].append('inline-sender-check')
    return found


def _split_args(tokens, start, end):
    """把实参列表按顶层逗号切开。"""
    args, current, depth = [], [], 0
    for i in range(start, end):
        text = tokens[i].text
        if text in '([{':
            depth += 1
        elif text in ')]}':
            depth -= 1
        if text == ',' and depth == 0:
            if current:
                args.append(current)
            current = []
            continue
        current.append(tokens[i])
    if current:
        args.append(current)
    return args

def closure(defs, roots, max_depth=3, max_nodes=200):
    """从 roots 出发，沿 calls 走 max_depth 层，返回能摸到的函数名（含 roots）。

    这是「跟调用链」的最小实现：不做类型推断、不分模块，只按名字连。
    连不到就是连不到——上限在那里，宁可少跟也不无限扩散。
    """
    seen = list(roots)
    frontier = list(roots)
    depth = 0
    while frontier and depth < max_depth and len(seen) < max_nodes:
        nxt = []
        for name in frontier:
            for callee in (defs.get(name) or {}).get('calls', ()):
                if callee not in seen:
                    seen.append(callee)
                    nxt.append(callee)
                    if len(seen) >= max_nodes:
                        break
            if len(seen) >= max_nodes:
                break
        frontier = nxt
        depth += 1
    return seen

