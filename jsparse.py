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




UNSEEN_CHARS = []
UNTERMINATED = []
MAX_UNSEEN = 500


def tokenize_with_stats(text):
    """切词，并把「认不出的字符」带回来。

    返回 (tokens, {'unseen': [字符…]})。认不出不是错误，是覆盖率的一部分；
    但必须能查——不然又是「出事了才知道」。
    """
    del UNSEEN_CHARS[:]
    del UNTERMINATED[:]
    tokens = tokenize(text)
    stats = {'unseen': list(UNSEEN_CHARS), 'unterminated': list(UNTERMINATED)}
    del UNSEEN_CHARS[:]
    del UNTERMINATED[:]
    return tokens, stats


def _matching_interp(text, start):
    """从 ${ 之后开始，找到配对的 }。字符串和嵌套模板都跳过。"""
    n = len(text)
    depth = 0
    i = start
    while i < n:
        ch = text[i]
        if ch in '\'"':
            quote = ch
            i += 1
            while i < n:
                if text[i] == '\\':
                    i += 2
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        if ch == '`':
            i += 1
            while i < n:
                if text[i] == '\\':
                    i += 2
                    continue
                if text[i] == '`':
                    i += 1
                    break
                i += 1
            continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            if depth == 0:
                return i
            depth -= 1
        i += 1
    return -1


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
                UNTERMINATED.append('comment')
                i = n
                continue
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
                # 打包产物里真会出现没有结尾的字符串（截断、拼接、奇怪编码）。
                # 到文件尾就收尾，不炸整份分析——这和「引号落单就断开」是同一条原则。
                UNTERMINATED.append('string')
            tokens.append(Token('string', text[start:i], start_line, start, i))
            continue
        if ch == '`':
            start, start_line = i, line
            i += 1
            while i < n:
                if text[i] == '\\':
                    i += 2
                    continue
                if text.startswith('${', i):
                    # 模板里的 ${...} 是**代码**，不是字符串内容。
                    # 早先这里直接跳过去了，结果打包产物里嵌在模板里的注册点
                    # 全被吞掉——Obsidian 那 16 条通道就是这么丢的。
                    close = _matching_interp(text, i + 2)
                    if close == -1:
                        i = n
                        break
                    inner = text[i + 2:close]
                    for token in tokenize(inner):
                        tokens.append(Token(token.kind, token.text, line + token.line,
                                            token.start + i + 2, token.end + i + 2))
                    line += inner.count('\n')
                    i = close + 1
                    continue
                if text[i] == '`':
                    i += 1
                    break
                if text[i] == '\n':
                    line += 1
                i += 1
            else:
                UNTERMINATED.append('template')
            tokens.append(Token('template', text[start:i], start_line, start, i))
            continue
        if ch == '#' and i + 1 < n and text[i + 1] in IDENT_START:
            # 私有字段 this.#x：把 #x 当成一个标识符，省得后面到处漏一个 '#'
            start = i
            i += 1
            while i < n and text[i] in IDENT_PART:
                i += 1
            tokens.append(Token('ident', text[start:i], line, start, i))
            continue
        if ch in IDENT_START:
            start = i
            while i < n and text[i] in IDENT_PART:
                i += 1
            tokens.append(Token('ident', text[start:i], line, start, i))
            continue
        if ch.isdigit():
            match = NUMBER_RE.match(text, i)
            if match is None:
                # 非 ASCII 数字（全角、阿拉伯-印度数字…）会进到这里：当普通标点，
                # 别让 match 是 None 时直接崩掉整份分析。
                tokens.append(Token('punct', ch, line, i, i + 1))
                i += 1
                continue
            tokens.append(Token('number', match.group(0), line, i, match.end()))
            i = match.end()
            continue
        if ch == '/' and i + 1 < n and _regex_allowed(tokens):
            # 正则里不该出现分号、也不该长到几百字符。
            # 真包踩过：打错的斜杠把后面一整段代码（含 ipcMain 注册）吞成了一个
            # 「正则」，那 16 条通道就这么消失的。看到分号就当它是除号，退回去。
            start = i
            i += 1
            in_class = False
            looks_like_code = False
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
                elif (text[i] == ';' and not in_class) or (text[i] == '\n' and not in_class):
                    looks_like_code = True
                    break
                i += 1
            if looks_like_code or (i - start) > 400:
                tokens.append(Token('punct', '/', line, start, start + 1))
                i = start + 1
                continue
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
        # 真包踩过：DeepSeek Harness 的一个文件里有 U+2026（…），词法器当场抛错，
        # 整个包的分析全废。认不出的字符不该炸掉整份分析——记下来、当标点跳过，
        # 让「覆盖率」是可读的数字，而不是一次崩溃。
        UNSEEN_CHARS.append(ch)
        tokens.append(Token('punct', ch, line, i, i + 1))
        i += 1
        continue
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



def method_defs(tokens):
    """对象字面量/赋值里的方法：`name: function(...) {...}`、`name = function(...) {...}`。

    这类函数没有 `function name` 头，原来的定义表抓不到，于是 `x.name()`
    这种调用永远建不起边。这是「字符串级粗扫」的天花板之一，先补这一种。
    """
    out = []
    for i in range(len(tokens) - 3):
        name, eq, fn = tokens[i], tokens[i + 1], tokens[i + 2]
        if name.kind != 'ident' or eq.text not in (':', '='):
            continue
        if fn.text != 'function':
            continue
        try:
            params_open = i + 3
            if tokens[params_open].text != '(':
                continue
            params_close = match_brace(tokens, params_open)
            body_open = params_close + 1
            if body_open >= len(tokens) or tokens[body_open].text != '{':
                continue
            body_close = match_brace(tokens, body_open)
        except ParseError:
            continue
        out.append({
            'name': name.text,
            'kind': 'method',
            'line': name.line,
            'body_start': body_open,
            'body_end': body_close,
        })
    return out


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



def unattributed_registrations(tokens, objects=None, samples=40, const_strings=None):
    """列出「注册了但名字不是字面量、也解不出来」的注册点。

    不只是个数：把卡住的那串表达式也带回来（this.channel、e.type…），
    这样报告能说「卡在什么形状上」，而不是只有一句「还有一些」。
    返回 [(行号, 表达式文本)]，最多 samples 条；总条数由调用方按 len 统计。
    """
    out = []
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
        resolved = False
        if first.kind == 'ident' and i + 4 < len(tokens) and tokens[i + 3].text in ('.', '?.'):
            owner, key = first.text, tokens[i + 4].text
            if objects and key in (objects.get(owner) or {}):
                resolved = True
        if resolved:
            continue
        if const_strings:
            # 常量表里唯一能定的，也算解出来了
            for ident_text in [t.text for t in tokens[i + 2:i + 8] if t.kind == 'ident']:
                values = const_strings.get(ident_text)
                if values and len(values) == 1:
                    resolved = True
                    break
        if resolved:
            continue
        # 取到第一个逗号为止，当作卡住的那段表达式
        expr = []
        depth = 0
        j = i + 2
        while j < len(tokens):
            text = tokens[j].text
            if text in ('(', '[', '{'):
                depth += 1
            elif text in (')', ']', '}'):
                if depth == 0:
                    break
                depth -= 1
            elif text == ',' and depth == 0:
                break
            expr.append(text)
            j += 1
        if len(out) < samples:
            out.append((tok.line + 1, ''.join(expr)))
    return out

def fold_literal_concat(tokens_slice):
    """把 `'a' + 'b'` 这种**纯字面量**拼接折成一个字符串，折不出就返 None。

    边界写死：只认 字符串 + 字符串 交替出现的形状。中间夹了变量、函数调用、
    模板占位符，一律不折——折错一次比不折坏得多，名字错了整份清单都跟着错。
    """
    if not tokens_slice:
        return None
    parts = []
    want_string = True
    for tok in tokens_slice:
        if want_string:
            if tok.kind not in ('string', 'template'):
                return None
            value = _string_of(tok)
            if value is None:
                return None
            parts.append(value)
            want_string = False
        else:
            if tok.text != '+':
                return None
            want_string = True
    if want_string:      # 结尾多了一个 +
        return None
    return ''.join(parts) if parts else None


def ipc_registrations(tokens, objects=None, const_strings=None):
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
        if channel is None and const_strings:
            # 三层成员链的解：X.Y.KEY → 拿包里唯一的字符串值兜回来。
            # 只认「唯一」：这个键在整包里有第二个不同值就放着不猜。
            idents = [t.text for t in first if t.kind == 'ident']
            for ident_text in reversed(idents):
                values = const_strings.get(ident_text)
                if values and len(values) == 1:
                    (only,) = values
                    if isinstance(only, str) and 0 < len(only) <= 200:
                        channel = only
                    break
        if channel is None:
            # 纯字面量拼接：`ipcMain.on('dyn-' + 'save', ...)`。
            # 这是静态能看见的、也确实算得出来的东西，没理由放过。
            folded = fold_literal_concat(first)
            if folded:
                channel = folded
        target, calls, guards = None, [], []
        # start_i/end_i 是 _window 的来源，必须两个分支都赋值——
        # 之前只在 else 分支赋，`ipcMain.on('x', handler)`（第二个参数是单个标识符）
        # 会走到第 642 行 UnboundLocalError 直接崩。抓样例时撞上的。
        start_i = end_i = 0
        if len(args) >= 2:
            second = args[1]
            if len(second) == 1 and second[0].kind == 'ident':
                target = second[0].text
                start_i = tokens.index(second[0])
                end_i = start_i + 1
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
        # 名字是变量（ipcMain.on(chName, ...)）时 channel 是 None。这种注册
        # **确实存在**，只是静态读不到它等于什么——所以不能当没看见，要把那个
        # 表达式本身记下来，回头进 unresolved_reasons['dynamic-registration']。
        first_expr = ' '.join(t.text for t in first) if (channel is None and first) else ''
        found.append({'channel': channel, 'target': target, 'span': span,
                      'calls': list(dict.fromkeys(calls)),
                      'guards': list(dict.fromkeys(guards)),
                      'first_expr': first_expr,
                      '_window': [t.text for t in tokens[start_i:end_i]], 'line': token.line + 1})
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

