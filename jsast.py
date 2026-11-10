"""一个够用的 JS 语法树：只认打包产物里真正会出现的那些结构。

为什么要有它：字符串级粗扫认不出 `x.y()` 到底调到了谁、回调传进去的是哪个函数，
所以「没看见危险调用」只能读成「两跳内没看见」。树建起来之后，这两件事才有答案。

设计上的取舍，都写在明处：
- 只解析**语句与表达式**这一层，装饰器、正则细节、JSX 一律不进来；
- 遇到不认识的记号就跳到下一个分号/右括号，不抛异常——目标是「在真包上跑得完」，
  不是「在规范上全对」；
- 每个函数节点记下自己的形参、局部 var 名、以及它直接发出的调用（名字 + 是不是成员调用）。
  作用域只做到「函数级 + 参数 + var 提升」，块级 let 不单独建作用域（会少认一点，不会多认）。
"""
import jsparse

KEYWORDS_STMT = {'if', 'for', 'while', 'do', 'switch', 'try', 'return', 'throw',
                 'break', 'continue', 'var', 'let', 'const', 'function', 'class',
                 'import', 'export', 'async', 'await', 'new', 'delete', 'typeof',
                 'in', 'of', 'instanceof', 'void', 'yield', 'case', 'default'}


class Node(object):
    __slots__ = ('kind', 'children', 'value')

    def __init__(self, kind, children=None, value=None):
        self.kind = kind
        self.children = children or []
        self.value = value

    def __repr__(self):
        return '<%s %r>' % (self.kind, self.value)


class Parser(object):
    def __init__(self, tokens):
        self.tokens = tokens
        self.pos = 0

    # --- 基础读写 ---
    def peek(self, offset=0):
        index = self.pos + offset
        if index < len(self.tokens):
            return self.tokens[index]
        return None

    def text(self, offset=0):
        token = self.peek(offset)
        return token.text if token else ''

    def take(self):
        token = self.peek()
        self.pos += 1
        return token

    def eat(self, text):
        if self.text() == text:
            self.pos += 1
            return True
        return False

    # --- 语句 ---
    def parse_program(self):
        body = []
        while self.peek() is not None:
            before = self.pos
            node = self.parse_statement()
            if node is not None:
                body.append(node)
            if self.pos == before:
                self.pos += 1  # 防死循环：认不出来就跳一个记号
        return Node('Program', body)

    def parse_statement(self):
        token = self.peek()
        if token is None:
            return None
        word = token.text

        if word == '{':
            return self.parse_block()
        if word in ('var', 'let', 'const'):
            return self.parse_var()
        if word == 'function':
            return self.parse_function(declaration=True)
        if word in ('async',) and self.text(1) == 'function':
            self.take()
            return self.parse_function(declaration=True)
        if word == 'class':
            self.take()
            name = self.text()
            if name and name not in ('{',):
                self.take()
            while self.peek() is not None and self.text() != '{':
                self.take()
            if self.text() == '{':
                return self.parse_block()
            return Node('Class', value=name)
        if word == 'if':
            self.take()
            cond = self.parse_paren_expression()
            then = self.parse_statement()
            other = None
            if self.text() == 'else':
                self.take()
                other = self.parse_statement()
            return Node('If', [x for x in (cond, then, other) if x is not None])
        if word in ('for', 'while'):
            self.take()
            header = self.parse_paren_expression()
            body = self.parse_statement()
            return Node('Loop', [x for x in (header, body) if x is not None])
        if word == 'do':
            self.take()
            body = self.parse_statement()
            if self.text() == 'while':
                self.take()
                self.parse_paren_expression()
            return Node('Loop', [body] if body else [])
        if word == 'try':
            self.take()
            block = self.parse_block()
            parts = [block] if block else []
            if self.text() == 'catch':
                self.take()
                if self.text() == '(':
                    self.parse_paren_expression()
                caught = self.parse_block()
                if caught:
                    parts.append(caught)
            if self.text() == 'finally':
                self.take()
                final = self.parse_block()
                if final:
                    parts.append(final)
            return Node('Try', parts)
        if word in ('return', 'throw'):
            self.take()
            expr = None
            if self.text() not in (';', '}', ''):
                expr = self.parse_expression()
            self.eat(';')
            return Node('Return' if word == 'return' else 'Throw',
                        [expr] if expr else [])
        if word == 'switch':
            self.take()
            header = self.parse_paren_expression()
            body = self.parse_block()
            return Node('Switch', [x for x in (header, body) if x is not None])
        if word in ('break', 'continue'):
            self.take()
            self.eat(';')
            return Node('Jump', value=word)
        if word in ('import', 'export'):
            # 打包产物里的 import 大多是静态导入，扫到分号/换行边界为止
            while self.peek() is not None and self.text() not in (';',):
                self.take()
            self.eat(';')
            return None

        expr = self.parse_expression()
        self.eat(';')
        return Node('ExprStatement', [expr] if expr else [])

    def parse_block(self):
        if not self.eat('{'):
            return None
        body = []
        while self.peek() is not None and self.text() != '}':
            before = self.pos
            node = self.parse_statement()
            if node is not None:
                body.append(node)
            if self.pos == before:
                self.pos += 1
        self.eat('}')
        return Node('Block', body)

    def parse_paren_expression(self):
        if not self.eat('('):
            return None
        expr = self.parse_expression()
        self.eat(')')
        return expr

    def parse_var(self):
        self.take()
        names = []
        inits = {}
        while True:
            name = None
            if self.peek() is not None and self.peek().kind == 'ident':
                name = self.text()
                names.append(name)
                self.take()
            if self.text() == '=':
                self.take()
                init = self.parse_assign()
                if name and init is not None:
                    inits[name] = init
            if self.text() == ',':
                self.take()
                continue
            break
        self.eat(';')
        # names 保持老形状（别处都在用），初值另放一份给别名判断用
        # 初值也要挂成子节点，否则 walk() 看不到里面的函数（对象方法就是这么丢的）
        return Node('Var', list(inits.values()), value={'names': names, 'inits': inits})

    def parse_function(self, declaration=False):
        self.take()  # function
        name = None
        if self.peek() is not None and self.peek().kind == 'ident':
            name = self.text()
            self.take()
        params = self.parse_params()
        body = self.parse_block()
        return Node('Function', [body] if body else [], value={'name': name, 'params': params})

    def parse_params(self):
        params = []
        if not self.eat('('):
            return params
        depth = 0
        while self.peek() is not None:
            token = self.peek()
            if token.text == '(':
                depth += 1
            elif token.text == ')':
                if depth == 0:
                    self.take()
                    break
                depth -= 1
            elif token.kind == 'ident' and depth == 0 and self.text(1) in (',', ')', '=', '}'):
                params.append(token.text)
            self.take()
        return params

    # --- 表达式 ---
    def parse_expression(self):
        return self.parse_assign()

    def parse_assign(self):
        left = self.parse_conditional()
        if self.text() in ('=', '+=', '-=', '*=', '/=', '||=', '&&=', '??='):
            op = self.take().text
            right = self.parse_assign()
            return Node('Assign', [x for x in (left, right) if x], value=op)
        return left

    def parse_conditional(self):
        test = self.parse_binary()
        if self.text() == '?':
            self.take()
            yes = self.parse_assign()
            self.eat(':')
            no = self.parse_assign()
            return Node('Conditional', [x for x in (test, yes, no) if x])
        return test

    def parse_binary(self, min_prec=0):
        left = self.parse_unary()
        prec = {'||': 1, '??': 1, '&&': 2, '|': 3, '^': 4, '&': 5,
                '==': 6, '!=': 6, '===': 6, '!==': 6,
                '<': 7, '>': 7, '<=': 7, '>=': 7, 'instanceof': 7, 'in': 7,
                '<<': 8, '>>': 8, '>>>': 8,
                '+': 9, '-': 9, '*': 10, '/': 10, '%': 10, '**': 11}
        while True:
            op = self.text()
            if op not in prec or prec[op] < min_prec:
                break
            self.take()
            right = self.parse_binary(prec[op] + 1)
            left = Node('Binary', [x for x in (left, right) if x], value=op)
        return left

    def parse_unary(self):
        word = self.text()
        if word in ('!', '-', '+', '~', 'typeof', 'void', 'delete', 'await', 'yield', '...'):
            self.take()
            operand = self.parse_unary()
            return Node('Unary', [operand] if operand else [], value=word)
        if word == 'new':
            self.take()
            callee = self.parse_call_member()
            args = self.parse_arguments() if self.text() == '(' else []
            return Node('New', [callee] + args, value='new')
        return self.parse_call_member()

    def parse_call_member(self):
        expr = self.parse_primary()
        while True:
            word = self.text()
            if word in ('.', '?.'):
                self.take()
                name = self.text()
                self.take()
                expr = Node('Member', [expr] if expr else [], value=name)
                continue
            if word == '(':
                args = self.parse_arguments()
                expr = Node('Call', [expr] + args)
                continue
            if word == '[':
                self.take()
                index = self.parse_expression()
                self.eat(']')
                expr = Node('Index', [x for x in (expr, index) if x])
                continue
            if word == '`' or (self.peek() is not None and self.peek().kind == 'template'):
                self.take()
                expr = Node('Template', [expr] if expr else [])
                continue
            break
        return expr

    def parse_arguments(self):
        args = []
        if not self.eat('('):
            return args
        while self.peek() is not None and self.text() != ')':
            args.append(self.parse_assign())
            if self.text() == ',':
                self.take()
                continue
            break
        self.eat(')')
        return [a for a in args if a is not None]

    def parse_primary(self):
        token = self.peek()
        if token is None:
            return None
        word = token.text
        if token.kind in ('string', 'template', 'number', 'regex'):
            self.take()
            return Node('Literal', value=word)
        if word in ('true', 'false', 'null', 'undefined', 'this', 'super'):
            self.take()
            return Node('Literal', value=word)
        if word == 'async' and self.text(1) in ('(', 'function'):
            # async (event, value) => {...}：以前只认 async function，箭头版整段丢了，
            # 剪贴板那条 fetch 就是这么漏的。
            self.take()
            if self.text() == 'function':
                return self.parse_function()
            return self.parse_primary()
        if word == 'function':
            return self.parse_function()
        if word == 'async' and self.text(1) == 'function':
            self.take()
            return self.parse_function()
        if word == '(':
            # 可能是箭头函数的参数表，也可能是普通括号
            saved = self.pos
            params = self.parse_params()
            if self.text() == '=>':
                self.take()
                body = self.parse_block() if self.text() == '{' else self.parse_assign()
                return Node('Function', [body] if body else [],
                            value={'name': None, 'params': params})
            self.pos = saved
            self.take()
            expr = self.parse_expression()
            self.eat(')')
            return expr
        if word == '{':
            return self.parse_object()
        if word == '[':
            return self.parse_array()
        if token.kind == 'ident':
            self.take()
            if self.text() == '=>':
                self.take()
                body = self.parse_block() if self.text() == '{' else self.parse_assign()
                return Node('Function', [body] if body else [],
                            value={'name': None, 'params': [word]})
            return Node('Ident', value=word)
        line = token.line + 1
        self.take()
        # 带上行号：未知节点要能指到 file:line，否则「归因」只是统计游戏
        return Node('Other', value={'text': word, 'line': line, 'col': token.start})

    def parse_object(self):
        self.take()  # {
        entries = []
        while self.peek() is not None and self.text() != '}':
            key = self.text()
            if self.text(1) in (':',):
                self.take()
                self.take()
                entries.append((key, self.parse_assign()))
            elif self.text(1) == '(':
                # 方法简写 name(...) { ... }
                name = self.take().text
                params = self.parse_params()
                body = self.parse_block()
                entries.append((name, Node('Function', [body] if body else [],
                                           value={'name': name, 'params': params,
                                                  'kind': 'method'})))
            else:
                self.take()
            if self.text() == ',':
                self.take()
                continue
            if self.text() in ('}', ''):
                break
        self.eat('}')
        # 值也挂成子节点：不然对象里的方法、嵌套函数都不在 walk 里
        return Node('Object', [v for _k, v in entries if v is not None], value=entries)

    def parse_array(self):
        self.take()
        items = []
        while self.peek() is not None and self.text() != ']':
            items.append(self.parse_assign())
            if self.text() == ',':
                self.take()
                continue
            break
        self.eat(']')
        return Node('Array', [x for x in items if x])


def parse(text):
    """源码 → 语法树。认不出来的地方跳过，不抛异常。"""
    return Parser(jsparse.tokenize(text)).parse_program()


# ---------------------------------------------------------------- 分析层
#
# 有了树之后能做两件粗扫做不到的事：
#   1. 成员调用 `a.b()` 按**方法名**连边（粗扫只能连 `b(` 这种裸调用）；
#   2. 回调传参：`arr.map(handler)` 里 handler 也是调用边。
# 作用域只做到函数级 + 形参 + var 名，块级 let 不单独建；
# 这条边界写在这儿，免得读的人以为我做了完整的名字解析。

def walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        if current is None:
            continue
        yield current
        for child in reversed(current.children):
            stack.append(child)


def functions_in(program, kinds=('any',)):
    """顶层与嵌套里的所有函数：名字 → 节点（同名的都留在列表里）。

    kinds 用来区分「声明式函数」和「对象字面量里的方法」：`t.flush()` 只该连到
    方法，不该连到同名的全局函数——那是两件不同的事，连错了就是假阳性。
    """
    out = {}
    for node in walk(program):
        if node.kind != 'Function':
            continue
        info = node.value or {}
        name = info.get('name')
        if not name:
            continue
        if 'any' not in kinds and info.get('kind', 'function') not in kinds:
            continue
        out.setdefault(name, []).append(node)
    return out


def locals_of(fn):
    names = set((fn.value or {}).get('params') or [])
    for node in walk(fn):
        if node.kind == 'Var':
            info = node.value or {}
            names.update(info.get('names') or [] if isinstance(info, dict) else (info or []))
        if node.kind == 'Function' and node is not fn:
            name = (node.value or {}).get('name')
            if name:
                names.add(name)
    return names


def calls_of(fn):
    """函数里发出的调用：[(种类, 名字)]。种类 ident / member / callback。"""
    out = []
    for node in walk(fn):
        if node.kind != 'Call' or not node.children:
            continue
        callee = node.children[0]
        if callee.kind == 'Ident':
            out.append(('ident', callee.value))
        elif callee.kind == 'Member':
            name = callee.value
            if name:
                out.append(('member', name))
        elif callee.kind == 'Index':
            # fs['readFileSync'](…) —— 方括号里的字符串也算方法名
            index = callee.children[1] if len(callee.children) > 1 else None
            if index is not None and index.kind == 'Literal' and index.value:
                text = index.value
                if text[:1] in ('"', "'", '`'):
                    out.append(('member', text[1:-1]))
        # 实参里直接写字面函数名的，也是调用边：map(handler)
        for arg in node.children[1:]:
            if arg is not None and arg.kind == 'Ident':
                out.append(('callback', arg.value))
    return out



def danger_aliases(fn, danger):
    """函数里的危险 API 别名：`const i = promisify(co.exec)` 这种。

    粗扫版靠正则猜，树版能看清「右边出现了谁」，一样只认这一种形状。
    """
    aliases = {}

    def remember(name, expr):
        if not name or expr is None:
            return
        for inner in walk(expr):
            if inner.kind == 'Ident' and inner.value in danger:
                aliases[name] = inner.value
                return
            if inner.kind == 'Member' and inner.value in danger:
                aliases[name] = inner.value
                return

    for node in walk(fn):
        if node.kind == 'Var':
            info = node.value or {}
            if isinstance(info, dict):
                for name, init in (info.get('inits') or {}).items():
                    remember(name, init)
            continue
        if node.kind == 'Assign' and len(node.children) >= 2:
            left, right = node.children[0], node.children[1]
            if left is not None and left.kind == 'Ident':
                remember(left.value, right)
    return aliases


def reachable_danger(program, roots, danger, max_depth=4, unique_by_name=True):
    """从 roots 出发，在树上算「能碰到哪些危险调用」，带回每一跳的名字。

    返回 {危险名: [路径…]}。同名函数只在「整个文件里只有一个定义」时连边，
    多个同名就记成 `名字?`——宁可用问号，也不假装知道是哪一个。
    """
    table = functions_in(program)
    methods = functions_in(program, kinds=('method',))
    out = {}
    seen = set()
    frontier = [(name, [name]) for name in roots]
    depth = 0
    while frontier and depth < max_depth:
        nxt = []
        for name, path in frontier:
            key = name
            if key in seen:
                continue
            seen.add(key)
            nodes = table.get(name) or []
            if not nodes:
                continue
            ambiguous = len(nodes) > 1 and unique_by_name
            for fn in nodes:
                local = locals_of(fn)
                aliases = danger_aliases(fn, danger)
                for kind, callee in calls_of(fn):
                    if callee in aliases:
                        api = aliases[callee]
                        out.setdefault(api, []).append('→'.join(path + [callee, api]))
                        continue
                    if callee in danger:
                        label = callee if kind != 'member' else callee
                        out.setdefault(label, []).append('→'.join(path + [label]))
                        continue
                    if kind == 'member' and callee in local:
                        continue
                    if kind == 'member':
                        if callee in methods:
                            nxt.append((callee, path + [callee]))
                        continue
                    if callee in table:
                        step = callee + ('?' if ambiguous else '')
                        nxt.append((callee, path + [step]))
            del local
        frontier = [item for item in nxt if item[0] not in seen]
        depth += 1
    return out


def reachable_from_roots(program, roots, danger, max_depth=5):
    """给定一批起点名字（通常是处理函数里直接出现的调用），在树上算可达的危险调用。

    和 reachable_danger 的区别：这里不假设起点本身是函数名，起点直接就是「被调用的名字」。
    返回 {危险名: [路径…]}。
    """
    table = functions_in(program)
    method_table = functions_in(program, kinds=('method',))
    out = {}
    seen = set()
    frontier = [(name, [name]) for name in roots]
    depth = 0
    while frontier and depth < max_depth:
        nxt = []
        for name, path in frontier:
            if name in seen:
                continue
            seen.add(name)
            if name in danger:
                # 起点本身就是危险 API：处理函数直接调了它，别再去函数表里找
                out.setdefault(name, []).append('→'.join(path))
                continue
            nodes = table.get(name) or []
            ambiguous = len(nodes) > 1
            for fn in nodes:
                aliases = danger_aliases(fn, danger)
                local = locals_of(fn)
                for kind, callee in calls_of(fn):
                    if callee in aliases:
                        api = aliases[callee]
                        out.setdefault(api, []).append('→'.join(path + [callee, api]))
                        continue
                    if callee in danger:
                        out.setdefault(callee, []).append('→'.join(path + [callee]))
                        continue
                    if kind == 'member' and callee in local:
                        continue
                    if kind == 'member':
                        if callee in method_table:
                            nxt.append((callee, path + [callee]))
                        continue
                    if callee in table:
                        step = callee + ('?' if ambiguous else '')
                        nxt.append((callee, path + [step]))
        frontier = [item for item in nxt if item[0] not in seen]
        depth += 1
    return out

