#!/usr/bin/env python3
"""ipcsurface — 把一个 Electron 应用的能力面压成一页纸。

两种输入：

- 一个 .asar 包：自己解包，按字符串粗扫一遍。零依赖，不用装 REA，答案糙但快。
- 一份 REA 的 Evidence JSON：语法级分析，答案准，前提是先跑一遍 REA。

不管是哪种，输出都只摆证据、不下结论，并且先说自己能信多少。
"""

import argparse
import datetime
import enum
import errno
import hashlib
import json
import mmap
import os
import re
import shutil
import struct
import sys
import tempfile
import time
import uuid
from collections import defaultdict

__version__ = '0.44.0'

HIGH_RISK_HINTS = ('__', 'internal', 'debug', 'admin')

# ---------------------------------------------------------------- asar

class AsarFiles:
    """asar 里的文件，谁要谁去切，不整包搬进内存。

    四百多兆的包里，有两百多兆是图片字体这类我们连碰都不碰的东西。
    以前一口气全读进来，峰值就是载荷的一倍多；现在只记偏移，
    按需从 mmap 里切片，切出来的那份用完就丢。
    """

    __slots__ = ('_fh', '_mm', '_spans')

    def __init__(self, path, spans):
        self._fh = open(path, 'rb')
        try:
            self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError):
            self._fh.close()
            raise
        self._spans = spans

    def __getitem__(self, rel):
        offset, size = self._spans[rel]
        return self._mm[offset:offset + size]

    def __contains__(self, rel):
        return rel in self._spans

    def __iter__(self):
        return iter(self._spans)

    def __len__(self):
        return len(self._spans)

    def get(self, rel, default=None):
        if rel in self._spans:
            return self[rel]
        return default

    def keys(self):
        return self._spans.keys()

    def items(self):
        for rel in self._spans:
            yield rel, self[rel]

    def values(self):
        for rel in self._spans:
            yield self[rel]

    def close(self):
        self._mm.close()
        self._fh.close()

    def total_bytes(self):
        """包里所有文件加起来的字节数。只查表，不搬内容。"""
        return sum(size for _offset, size in self._spans.values())

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False


def read_asar(path):
    """解一个 asar，返回 (文件树, 文件表)。

    asar 的头是个 pickle：8 字节前缀，其中后 4 字节是头部长度；
    头部本身又是 4 字节长度 + JSON。

    文件表不装内容，只装位置。要哪份切哪份。
    """
    with open(path, 'rb') as fh:
        head = fh.read(8)
        if len(head) < 8:
            raise SystemExit('这不是 asar：文件太短')
        header_size = struct.unpack('<I', head[4:8])[0]
        payload = fh.read(header_size)
        if len(payload) < header_size:
            raise SystemExit('这不是 asar：头部被截断')
        # 头部是层叠的 pickle：几层长度前缀，后面才是 JSON。
        # 不数层数，直接找第一个 { 让它自己解，省得跟着版本变。
        text = payload.decode('utf-8', 'replace')
        start = text.find('{')
        if start < 0:
            raise SystemExit('这不是 asar：头部找不到 JSON')
        try:
            header, _ = json.JSONDecoder().raw_decode(text[start:])
        except json.JSONDecodeError:
            raise SystemExit('这不是 asar：头部不是合法 JSON')
        base = 8 + header_size

    spans = {}

    def walk(node, prefix):
        for name, child in (node.get('files') or {}).items():
            rel = f'{prefix}{name}'
            if 'files' in child:
                walk(child, rel + '/')
            else:
                offset = int(child.get('offset', 0))
                size = int(child.get('size', 0))
                spans[rel] = (base + offset, size)

    walk(header, '')
    return header, AsarFiles(path, spans)


TEXT_EXT = ('.js', '.mjs', '.cjs', '.jsx', '.ts', '.json', '.html', '.asar')

PATTERNS = [
    ('expose', re.compile(r"exposeInMainWorld\(\s*['\"]([^'\"]+)['\"]")),
    # ipcMain.handle(...) 和 ipcMain['handle'](...) 是同一件事，后者只是写法绕。
    ('handle', re.compile(r"ipcMain(?:\.(?:handle|handleOnce|on)|\[\s*['\"](?:handle|handleOnce|on)['\"]\s*\])"
                          r"\(\s*['\"]([^'\"]+)['\"]")),
    ('invoke', re.compile(r"ipcRenderer(?:\.(?:invoke|send|sendSync)|\[\s*['\"](?:invoke|send|sendSync)['\"]\s*\])"
                          r"\(\s*['\"]([^'\"]+)['\"]")),
    ('dynamic_handle', re.compile(r"ipcMain(?:\.(?:handle|on)|\[\s*['\"](?:handle|on)['\"]\s*\])"
                                  r"\(\s*([^'\"\s][^,)]*\)?)")),
    ('dynamic_invoke', re.compile(r"ipcRenderer(?:\.(?:invoke|send)|\[\s*['\"](?:invoke|send)['\"]\s*\])"
                                  r"\(\s*([^'\"\s][^,)]*\)?)")),
    ('preload', re.compile(r"preload\s*:\s*([^,\n}]+)")),
    ('contextIsolation', re.compile(r"contextIsolation\s*:\s*(\w+)")),
    ('nodeIntegration', re.compile(r"nodeIntegration\s*:\s*(\w+)")),
    ('sandbox', re.compile(r"sandbox\s*:\s*(\w+)")),
]


def line_of(text, pos):
    return text.count('\n', 0, pos) + 1


def stamp():
    """报告里带生成时间和版本——审出来的东西要能对上号。"""
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    return f'生成于 {now}，ipcsurface {__version__}'


# 分两档。strong 才算「这包被人动过」，weak 只是常见写法，报出来供参考。
OBF_PATTERNS = [
    ('eval 直接执行字符串', re.compile(rb'\beval\s*\('), 'strong', b'eval'),
    ('十六进制标识符', re.compile(rb'\b_0x[0-9a-fA-F]{2,}'), 'strong', b'_0x'),
    ('超长单行（压过）', re.compile(rb'[^\n]{2000,}'), 'strong', None),
    ('base64 现场解码', re.compile(rb'\batob\s*\('), 'weak', b'atob'),
    ('Function 构造器拼代码', re.compile(rb'\bnew\s+Function\s*\('), 'weak', b'Function'),
    ('charCode 拼字符串', re.compile(rb'fromCharCode'), 'weak', b'fromCharCode'),
]


# 字符串字面量相加，先折成一段：'ledger:' + 'add' → 'ledger:add'
# 只折两头都是纯字面量的，别的一律不动。行数不变，行号还能对得上。
CONCAT_QUOTES = re.compile(r"""(['"])([^'"\\]*)\1\s*\+\s*(['"])([^'"\\]*)\3""")


# 混淆最常见的一招：名字提到数组里，代码里按数字取。
#   var _0x4a2f = ['ledger', ':', 'add'];
#   ipcMain.handle(_0x4a2f[0], ...)
# 这一层不用解释器：找到数组、找到下标，换成字面量就行。
ARRAY_DECL = re.compile(r"(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*\[([^\]]{0,6000})\]")
INDEX_USE = re.compile(r"([A-Za-z_$][\w$]*)\s*\[\s*(\d{1,3})\s*\]")
LIT_IN_ARRAY = re.compile(r"""(['"])((?:\\.|(?!\1)[^\\])*)\1""")


def restore_string_arrays(text):
    """把「字符串池 + 数字下标」这层拆掉。

    只认最直白的那种：一个变量存了个全字符串的数组，后面按下标取。
    取值里的解码函数、二次引用、拆分存储，这一层都还原不了——那些得算值，
    算值就得执行，不在这儿干。
    """
    pools = {}
    for match in ARRAY_DECL.finditer(text):
        name, body = match.group(1), match.group(2)
        items = [m.group(2) for m in LIT_IN_ARRAY.finditer(body)]
        # 全是字符串、起码三个，才当字符串池看。零零散散的数组不算。
        if len(items) >= 3 and len(items) == len(re.findall(r"""(['"]).*?\1""", body, re.S)):
            pools[name] = items
    if not pools:
        return text

    def replace(match):
        name, index = match.group(1), int(match.group(2))
        items = pools.get(name)
        if items and 0 <= index < len(items):
            return "'" + items[index] + "'"
        return match.group(0)

    return INDEX_USE.sub(replace, text)


# 解码函数长得有数。认得出形状的，用纯 Python 算；认不出就放弃。
# 这样不执行目标里的任何代码，也就不用沙箱，可以直接开着。
DECODE_SHAPES = [
    (re.compile(r'charCodeAt\([^)]*\)\s*\^\s*(\d+)'), 'xor'),
    (re.compile(r'charCodeAt\([^)]*\)\s*\+\s*(\d+)'), 'add'),
    (re.compile(r'charCodeAt\([^)]*\)\s*-\s*(\d+)'), 'sub'),
]


def build_decoder(body):
    """看函数体的形状，挑一个纯 Python 的实现。认不出返回 None。

    只认这几种：逐字符异或、加、减，还有整体反转。
    别的形状一律放弃——猜出来的值比没有更坏。
    """
    if 'fromCharCode' in body:
        for pattern, kind in DECODE_SHAPES:
            match = pattern.search(body)
            if not match:
                continue
            shift = int(match.group(1))
            if shift > 0xFFFF:
                return None
            if kind == 'xor':
                return lambda s, k=shift: _map_chars(s, lambda n: n ^ k)
            if kind == 'add':
                return lambda s, k=shift: _map_chars(s, lambda n: n + k)
            return lambda s, k=shift: _map_chars(s, lambda n: n - k)
    if 'reverse()' in body and 'join(' in body and 'split(' in body:
        return lambda s: s[::-1]
    return None


JS_ESC = re.compile(r'\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|.)')


def js_unescape(text):
    """把 JS 字符串里的转义还原成真字符。\\x71 变成 q 那种。"""
    def replace(match):
        seq = match.group(1)
        if seq[0] in 'xu' and len(seq) > 1:
            return chr(int(seq[1:], 16))
        return {'n': '\n', 't': '\t', 'r': '\r', '0': '\0',
                '\\': '\\', "'": "'", '"': '"'}.get(seq, seq)
    return JS_ESC.sub(replace, text)


def _map_chars(text, fn):
    """一个字符一个字符地变换。落在可打印范围外就当算不出来。"""
    out = []
    for ch in text:
        value = fn(ord(ch))
        if not 0 <= value <= 0x10FFFF:
            return None
        out.append(chr(value))
    return ''.join(out)
FUNC_HEAD = re.compile(r'function\s+([A-Za-z_$][\w$]*)\s*\(([^)]{0,120})\)\s*\{')


def find_functions(text):
    """找出函数定义，连大括号一起配平。

    正则数不清嵌套的 { }，只好自己数。单行函数和跨行函数都要认。
    """
    found = []
    for match in FUNC_HEAD.finditer(text):
        start = match.end() - 1
        depth = 0
        for i in range(start, len(text)):
            ch = text[i]
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    found.append((match.group(1), match.group(2), text[start + 1:i]))
                    break
    return found
DECODE_HINTS = ('charCodeAt', 'fromCharCode', 'substr', 'slice(', 'split(', 'reverse(',
                'join(', 'from(', 'toString(16')


def _node_eval(code):
    """把一小段代码交给 Node 沙箱算。算不出来就返回 None，不猜。"""
    import subprocess
    try:
        proc = subprocess.run(['node', EVAL_JS], input=code, capture_output=True,
                              text=True, timeout=10, encoding='utf-8')
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    last = proc.stdout.strip().splitlines()[-1]
    try:
        data = json.loads(last)
    except json.JSONDecodeError:
        return None
    return data.get('value') if data.get('ok') else None


def restore_decode_calls(text):
    """把「自解码函数 + 字面量参数」这种算出来。

    一轮只能拆一层：`_d(_e('xx'))` 得先算里面那层，再算外面。
    所以来回跑几轮，直到不再变化。层数深就多跑几轮。
    """
    for _ in range(6):
        updated = _restore_one_pass(text)
        if updated == text:
            break
        text = updated
    return text


def _restore_one_pass(text):
    defs = {}
    for name, params, body in find_functions(text):
        decoder = build_decoder(body)
        if decoder is not None:
            defs[name] = decoder
    if not defs:
        return text

    for name, decoder in defs.items():
        # 参数必须是写死的字符串，单双引号都认。带引号整段留住，
        # 这样套两层的时候，里层算完变成 "vault:unlock"，外层还能接着认。
        call = re.compile(re.escape(name) + r"""\(\s*('[^'\n]{1,300}'|"[^"\n]{1,300}")\s*\)""")

        def replace(match, decoder=decoder):
            literal = match.group(1)[1:-1]
            value = decoder(js_unescape(literal))
            if value is None:
                return match.group(0)
            return json.dumps(value, ensure_ascii=False)

        text = call.sub(replace, text)
    return text


TPL_STRING = re.compile(r'`([^`\\]{0,300})`')
TPL_LITERAL = re.compile(r"\$\{\s*(['\"])((?:\\.|(?!\1)[^\\]){1,80})\1\s*\}")


def fold_templates(text):
    """模板串里只插字面量的，直接摊平：`ledger:${'tpl'}` → "ledger:tpl"。

    插值是变量的不碰——那要算运行时的值，不在这儿猜。
    套在别的模板里面的也不碰：`` `a:${`b`}` `` 要是把里层摊成 "b"，
    外层那段就变形了，报告里会印出一截谁也看不懂的东西。
    """
    pieces = []
    pos = 0
    while True:
        match = TPL_STRING.search(text, pos)
        if not match:
            break
        body = match.group(1)
        # 体里还有没闭合的 ${ ，说明这段是被里面那层反引号截断的。
        # 从这儿到下一个反引号之间原样留着，一个字都不改。
        if body.count('${') > body.count('}'):
            nxt = text.find('`', match.end())
            if nxt < 0:
                break
            pieces.append(text[pos:nxt + 1])
            pos = nxt + 1
            continue
        flattened = TPL_LITERAL.sub(lambda m: m.group(2), body)
        pieces.append(text[pos:match.start()])
        if '${' in flattened or '\n' in body:
            # 带换行的模板摊平会把行数压掉，行号一错，报告里的定位就全废了。
            pieces.append(match.group(0))
        else:
            pieces.append(json.dumps(flattened, ensure_ascii=False))
        pos = match.end()
    pieces.append(text[pos:])
    return ''.join(pieces)


UNICODE_ESCAPE = re.compile(r'\\u([0-9a-fA-F]{4})')
QUOTED = re.compile(r"""(['"])((?:\\.|(?!\1)[^\\])*)\1""")


def decode_unicode_strings(text):
    """字面量里的 \\u0075 这种，先还原成真字符。

    只在引号里面动，而且还原出来的要是引号或反斜杠就跳过——
    不然一个转义反手把整个字符串的边界拆了，后面全乱。
    """

    def fix(match):
        body = match.group(2)
        if '\\u' not in body:
            return match.group(0)
        quote = match.group(1)

        def one(m):
            char = chr(int(m.group(1), 16))
            # 引号、反斜杠会拆掉字符串边界；控制字符会把行数撑开，
            # 行号一乱，报告里的定位就全废了。这几类一概不还原。
            if char in ('"', "'", '\\') or ord(char) < 0x20:
                return m.group(0)
            return char

        return quote + UNICODE_ESCAPE.sub(one, body) + quote

    return QUOTED.sub(fix, text)


CONST_DEF = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]{3,})\s*=\s*"
                       r"""(['"])((?:\\.|(?!\2)[^\\]){1,120})\2\s*;""")


# 标识符后面跟着 + 号：常量代回去的落点。扫形状再查表，比拼巨型正则便宜。
IDENT_BEFORE_PLUS = re.compile(r'(?<![\w$.])([A-Za-z_$][\w$]*)(\s*\+)')
# 对象.字段：常量对象还原的落点
MEMBER_ACCESS = re.compile(r'(?<![\w$.])([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)')


def propagate_constants(text, extra=None):
    """把 `const PREFIX = 'ledger:'` 这种常量，代回到拼接的地方。

    extra 是从全包别处收来的常量表——跨文件那种。只认名字够长的，
    撞车的可能性小一点。本文件自己的定义优先。
    """
    constants = {m.group(1): m.group(3) for m in CONST_DEF.finditer(text)}
    if extra:
        # 只拿这段代码里真的出现过的名字。几千个常量挨个试，会把 4 秒变成 95 秒。
        for name, value in extra.items():
            if name in text:
                constants.setdefault(name, value)
    if not constants:
        return text
    # 不用把几千个名字拼成一条巨型正则——拼一次就是几千次转义，
    # 直接在标识符上扫一遍再查表，一个正则走到底。
    def replace(match):
        value = constants.get(match.group(1))
        if value is None:
            return match.group(0)
        return json.dumps(value, ensure_ascii=False) + match.group(2)

    return IDENT_BEFORE_PLUS.sub(replace, text)


IPC_ARG = re.compile(r'(ipcMain(?:\.(?:handle|handleOnce|on)|\[\s*[\'"](?:handle|handleOnce|on)[\'"]\s*\])'
                     r'|ipcRenderer(?:\.(?:invoke|send)|\[\s*[\'"](?:invoke|send)[\'"]\s*\]))'
                     r'\(\s*([A-Za-z_$][\w$]*)\s*([,)])')


def resolve_ipc_arg(text, extra=None):
    """`ipcMain.handle(CHANNEL_NAME, …)` 这种，把常量换回它的值。

    名字可能定义在另一个文件里，所以要靠 extra 那张全包的表。
    """
    if not extra:
        return text

    def replace(match):
        name = match.group(2)
        value = extra.get(name)
        if value is None:
            return match.group(0)
        return f'{match.group(1)}({json.dumps(value, ensure_ascii=False)}{match.group(3)}'

    return IPC_ARG.sub(replace, text)


def fold_literals(text):
    for _ in range(4):
        folded = CONCAT_QUOTES.sub(
            lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), text)
        if folded == text:
            break
        text = folded
    return text


def detect_obfuscation(blob, rel):
    """在字节上找混淆特征。这几条全是 ASCII，不必先解码。

    每条先拿一个必现的子串探一下，探不到就不跑正则。
    正则再快也比不过 memchr 找一遍字节；大部分文件只中一两条，
    六条全跑一遍是白烧。
    """
    hits = []
    for name, pattern, level, needle in OBF_PATTERNS:
        if needle is not None:
            if needle not in blob:
                continue
        elif len(blob) < 2000:
            # 整个文件都不到 2000 字节，里面不可能有一行 2000 字符
            continue
        match = pattern.search(blob)
        if match:
            line = blob.count(b'\n', 0, match.start()) + 1
            hits.append((name, f'{rel}:{line}', level))
    return hits


# 定义常量离不开 const/let/var，没有这几个词的文件不必解码。
CONST_HINTS = (b'const', b'let ', b'let\t', b'let\n', b'var ', b'var\t', b'var\n')


# 常量对象：const CH = { boot: 'dsh-desktop:boot', … }，代码里写 CH.boot。
# 这种名字以前只能标成「算出来的」，其实表就在文件里，抄出来就行。
OBJECT_DEF = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\{([^{}]{0,4000})\}")
OBJECT_FIELD = re.compile(r"""([A-Za-z_$][\w$]*)\s*:\s*(['"])((?:\\.|(?!\2)[^\\])*)\2""")


def parse_object_literals(text):
    """把文件里「常量对象」的字段摊平：{对象名: {字段: 值}}。"""
    table = {}
    for match in OBJECT_DEF.finditer(text):
        name, body = match.group(1), match.group(2)
        fields = {key: value for key, _quote, value in OBJECT_FIELD.findall(body)}
        if fields:
            table.setdefault(name, {}).update(fields)
    return table


def build_global_members(files):
    """跨文件的常量对象表。名字写在 a.js、用的地方在 b.js，也得配得上。"""
    table = {}
    for rel, blob in files.items():
        if not rel.endswith(JS_EXT) or len(blob) > 300_000:
            continue
        if b'{' not in blob or b':' not in blob:
            continue
        try:
            text = blob.decode('utf-8')
        except UnicodeDecodeError:
            text = blob.decode('latin-1', 'ignore')
        for name, fields in parse_object_literals(text).items():
            table.setdefault(name, {}).update(fields)
    return table


def propagate_members(text, table):
    """把 `CH.boot` 换成它登记的值。查不到就原样留着，不猜。"""
    if not table:
        return text

    def replace(match):
        fields = table.get(match.group(1))
        if not fields:
            return match.group(0)
        value = fields.get(match.group(2))
        if value is None:
            return match.group(0)
        return json.dumps(value, ensure_ascii=False)

    return MEMBER_ACCESS.sub(replace, text)


def build_global_tables(files):
    """一趟走完，把两种表都收了：普通常量和常量对象。

    以前是两趟，等于把两万多个文件解码两遍。这种事写起来顺手，跑起来贵。
    """
    consts, members = {}, {}
    for rel, blob in files.items():
        if not rel.endswith(JS_EXT) or len(blob) > 300_000:
            continue
        if b'=' not in blob:
            continue
        has_quote = b"'" in blob or b'"' in blob
        # 常量对象一定长成 `X = {`；没这个形状的文件不必跑那条正则
        has_object = b'= {' in blob or b'={' in blob
        if not has_quote and not has_object:
            continue
        try:
            text = blob.decode('utf-8')
        except UnicodeDecodeError:
            text = blob.decode('latin-1', 'ignore')
        for match in CONST_DEF.finditer(text):
            name, value = match.group(1), match.group(3)
            if len(name) >= 6 and name not in consts:
                consts[name] = value
        if has_object and b':' in blob:
            for name, fields in parse_object_literals(text).items():
                members.setdefault(name, {}).update(fields)
    return consts, members


def build_global_constants(files):
    """先把所有文件里的字符串常量收成一张表。

    跨文件的常量看不见——`const CHANNEL = 'vault:unlock'` 写在 a.js，
    `ipcMain.handle(CHANNEL)` 写在 b.js。一个文件一个文件扫，永远配不上。
    这一步先扫一遍建表，第二遍才有得查。

    名字太短的不收，会撞车。同一个名字出现两次也只留第一份。
    """
    table = {}
    for rel, blob in files.items():
        if not rel.endswith(JS_EXT):
            continue
        # 太大的多半是打包产物，常量几千个，收了也没用，还慢
        if len(blob) > 300_000:
            continue
        # 没有 const/let/var 就定义不出常量，连解码都省了
        if not any(hint in blob for hint in CONST_HINTS):
            continue
        if b'=' not in blob or (b"'" not in blob and b'"' not in blob):
            continue
        try:
            text = blob.decode('utf-8')
        except UnicodeDecodeError:
            text = blob.decode('latin-1', 'ignore')
        for match in CONST_DEF.finditer(text):
            name, value = match.group(1), match.group(3)
            if len(name) >= 6 and name not in table:
                table[name] = value
    return table


RESTORE_STEPS = 6
# 还能不能有下一趟。这几样都不剩了，再转一趟纯属白跑。
RESTORE_HINTS = ('_0x[', '${', '\\u', "' + ", '" + ', "'+", '"+')


def restore_all(text, allow_eval=True, extra=None, members=None, original_size=None,
                max_passes=1):
    """还原。默认只走一趟，`--deep-restore` 才多转几趟。

    走到两趟以上是为了这种写法：先还原字符串池，露出一段模板串，
    再摊平模板才得到真名。但还原顺序本来就排好了——数组在模板前、
    模板在常量前——所以这类链条一趟就走完了。

    留这个开关是因为换一批样本可能有别的顺序问题；默认关着，
    是因为实测多转一趟在这批样本上一条都没多认出，白花 1.6 秒。
    """
    original_size = original_size if original_size is not None else len(text)
    passes = 0
    unstable = False
    limit = max(1, max_passes if max_passes > 1 else 1)
    for _ in range(limit):
        before = text
        text = restore_string_arrays(text)
        if allow_eval:
            text = restore_decode_calls(text)
        text = decode_unicode_strings(text)
        text = fold_templates(text)
        text = propagate_constants(text, extra=extra)
        text = propagate_members(text, members or {})
        text = resolve_ipc_arg(text, extra=extra)
        text = fold_literals(text)
        passes += 1
        if text == before:
            break
        if len(text) > max(original_size * 3, original_size + 65536):
            # 越还原越大，说明碰上了解不开的写法，收手，别再往坏里改
            unstable = True
            text = before
            break
        if not any(hint in text for hint in RESTORE_HINTS):
            break   # 已经没有什么能再还原的了，别白转
    return text, passes, unstable


def scan_asar(files, allow_eval=True, max_passes=1):
    """按字符串扫一遍源码。粗，但不用装任何东西。"""
    exposes, handlers, invokes = [], [], []
    dynamic, prefs, preloads = [], {}, []
    obfuscation = []
    resolved = set()   # 靠还原才认出名字的那些，强度低一档
    scanned = 0
    # 先收一遍全包的常量，跨文件那种才配得上
    global_consts, global_members = build_global_tables(files)

    for rel, blob in files.items():
        if not rel.endswith(TEXT_EXT):
            continue
        # 先用字节找标记。解成字符串再找，慢十倍不止。
        hot_ipc = (b'ipcMain' in blob or b'contextBridge' in blob
                   or b'webPreferences' in blob)
        suspicious = (b'eval(' in blob or b'_0x' in blob or b'atob(' in blob
                      or b'new Function(' in blob)
        if not hot_ipc and not suspicious:
            continue
        # 混淆特征在字节上就能认，先认完再决定要不要解码
        if suspicious:
            obfuscation.extend(detect_obfuscation(blob, rel))
        if not hot_ipc:
            continue
        try:
            text = blob.decode('utf-8')
        except UnicodeDecodeError:
            text = blob.decode('latin-1', 'ignore')
        # 原文先扫一遍，记下哪些名字是「写在那儿」的。
        # 还原之后才出现的，和它不是一个强度，别混着算。
        literal_names = set()
        for kind, pattern in PATTERNS:
            if kind in ('handle', 'invoke'):
                for match in pattern.finditer(text):
                    literal_names.add(match.group(1).strip())

        text = restore_all(text, allow_eval=allow_eval, extra=global_consts,
                           members=global_members, original_size=len(text),
                           max_passes=max_passes)[0]
        scanned += 1
        for kind, pattern in PATTERNS:
            for match in pattern.finditer(text):
                where = f'{rel}:{line_of(text, match.start())}'
                value = match.group(1).strip()
                if kind == 'expose':
                    exposes.append((value, where))
                elif kind in ('handle', 'invoke'):
                    # 后面紧跟 + 或 . 说明这个名字只是拼的前半截
                    rest = text[match.end():match.end() + 4].lstrip()
                    if rest[:1] in ('+', '.'):
                        dynamic.append((f'{kind}: {value} + …', where))
                        continue
                    if value not in literal_names:
                        resolved.add(value)
                    (handlers if kind == 'handle' else invokes).append((value, where))
                elif kind in ('dynamic_handle', 'dynamic_invoke'):
                    if not value.startswith(("'", '"')):
                        dynamic.append((f'{kind.split("_")[1]}: {value}', where))
                elif kind == 'preload':
                    preloads.append((value, where))
                else:
                    prefs[kind] = (value, where)

    return {
        'scanned': scanned,
        'exposes': sorted(set(exposes)),
        'handlers': sorted(set(handlers)),
        'invokes': sorted(set(invokes)),
        'dynamic': sorted(set(dynamic)),
        'preloads': sorted(set(preloads)),
        'prefs': prefs,
        'obfuscation': sorted(set(obfuscation))[:200],
        'native_files': sorted(rel for rel in files if rel.endswith(('.node', '.dll'))),
        'nested_asar': sorted(rel for rel in files if rel.endswith('.asar')),
        'resolved': sorted(resolved),
        # 通道就是主进程注册和页面侧调用的那些名字，不含 window 上暴露的 API。
        # 口径要和报告里「N 条通道」一致，否则基线存一份、报告说另一份。
        'channels': sorted({name for name, _w in handlers} | {name for name, _w in invokes}),
    }


def audit_asar(facts):
    """粗扫也有可疑项。不然挂在 CI 上的 --fail-on 在这条路上等于没用。"""
    findings = []
    for name, where, level in facts['obfuscation']:
        if level == 'strong':
            findings.append(('high', f'强混淆指纹：{name}', where))
    for name, where in facts['handlers']:
        low = name.lower()
        if any(hint in low for hint in HIGH_RISK_HINTS):
            findings.append(('medium', f'通道名带隐藏意味：{name}', where))
    return findings


# 独立性判定表：不是举几个例子，是把全部两两组合写死。没点名的地方最容易按自己的理解走。
STATIC_SOURCES = ('literal', 'literal-resolved', 'computed', 'harvested')
ALL_SOURCES = STATIC_SOURCES + ('runtime',)


def _build_independence():
    table = {}
    for i, left in enumerate(ALL_SOURCES):
        for right in ALL_SOURCES[i + 1:]:
            pair = '|'.join(sorted((left, right)))
            # 同一个包的两条静态读法共享同一份源码和同一张常量表，不算独立见证；
            # 运行时是另一条路，和任一静态来源都独立。
            table[pair] = (left == 'runtime') != (right == 'runtime')
    return table


INDEPENDENCE_TABLE = _build_independence()


def independent(left, right):
    return INDEPENDENCE_TABLE['|'.join(sorted((left, right)))]


CORROBORATION_KINDS = {
    'static_runtime': '静态（逐字或查表）与运行时各看见一次，两边互不依赖',
    'static_static': '两个静态来源对上了，但都在静态侧，只是写法不同，不算独立见证',
    'none': '只有一条路看见',
}


# 规则登记表。每条规则一个 id，测试里必须有 test_rule_<id> 开头的用例，
# 否则 meta-test 会红。这样「每条规则配用例」是能被检查的，不是靠着记。
RULES = [
    {'id': 'independence_table',
     'text': '独立性按全部两两组合判定，不靠举例；静态来源之间不算独立，运行时与任一静态来源算'},
    {'id': 'primary_action_not_alone',
     'text': 'primary_action 只是先做哪件事，不能替代 actions'},
    {'id': 'input_errors_are_typed',
     'text': '输入错误的类别要能被机器读到（kind: xxx），中文文案只是附属；'
             '下游决定重试还是放弃，不该去解析中文'},
    {'id': 'depth_limit_is_explicit',
     'text': 'JSON 嵌套上限是显式常量 MAX_JSON_DEPTH，超了直接按 depth_exceeded 拒，'
             '不靠撞上 RecursionError 再兜底——那样换 Python 版本行为会漂'},
    {'id': 'output_is_all_or_nothing',
     'text': '写报告要么完整写出来，要么一个字节都不留；写到一半失败要按类别拒绝，'
             '不许留下看起来正常的半成品，也不许拿它盖掉上一份完整的报告'},
    {'id': 'backup_age_from_filename',
     'text': '备份年龄只认文件名里的时间戳：ctime 在 Linux 是 inode 变更时间、'
             'Windows 是创建时间、网络盘各说各话，靠它判年龄是「碰巧对」而不是「可靠」'},
    {'id': 'report_matches_golden_snapshot',
     'text': '固定输入 → 固定输出，逐字段比金标准；把「这次重构没改行为」从一次性对比'
             '变成以后每次都验'},
    {'id': 'assertions_declare_non_empty',
     'text': '对集合做全称断言前先断言集合非空：对空集合说「全都满足」平凡为真，'
             '这种绿比红更危险。反向守卫（前提变了会红）要在消息里自己说明「不是回归」'},
    {'id': 'md_and_json_agree_on_counts',
     'text': 'md 报告里的通道数必须等于 JSON 的 channels 长度；这个口径差过一次（41 对 52）'},
    {'id': 'md_sections_are_unique',
     'text': 'md 报告也是输出契约：章节标题与编号都不许重复（这个毛病真出过）'},
    {'id': 'report_keys_are_whitelisted',
     'text': '报告 JSON 的顶层键必须在 REPORT_TOP_LEVEL_KEYS 白名单里；'
             '多一个键就红——「别把 durable 之类写进报告」从文档承诺变成回归约束'},
    {'id': 'cleanup_checks_target_before_age',
     'text': '清副本先判 target 在不在，再判年龄：反过来的话时钟大幅前跳会让一批副本'
             '同时变成过期候选，只能逐个救回来'},
    {'id': 'failed_dump_keeps_shorter_window',
     'text': '.failed 里是报告正文（可能带路径与通道名），保留窗口只有 6 小时，'
             '比副本的 24 小时短——诊断价值随时间衰减，敏感留存不衰减'},
    {'id': 'foreign_backup_is_not_touched',
     'text': '只清自己生成的名字（.{名}.{13位时间戳}.{8位hex}.bak/.failed），'
             '用户手工放的 report.md.bak 不动、也不误报'},
    {'id': 'dir_fsync_failure_is_reported',
     'text': '目录 fsync 失败不是写失败：内容已经替换，只是崩溃后可能回退。'
             '这个状态要能被观察到（WriteResult.durable + 警告），不能压成一个「成功」'},
    {'id': 'stale_backup_needs_target',
     'text': '清孤儿副本前先看 target 在不在：target 都没了，那份副本可能是唯一的旧版，'
             '留着并提醒，不擅自删'},
    {'id': 'symlink_target_is_refused',
     'text': '目标路径是符号链接就拒绝：备份跟随链接复制内容，替换却把链接变成普通文件，'
             '两头语义不一致，让调用方自己给 realpath'},
    {'id': 'output_verified_before_replace',
     'text': '能核的一律在替换前核完（字节数、JSON 可解析）；替身成功后不再核内容——'
             'replace 成功就说明 target 等于 tmp，再比一遍是恒真，那条还原分支永远不会被真实触发'},
    {'id': 'silent_wrong_count_is_caught',
     'text': '最高优先级：报一个格式合法但数值错的通道数，比崩掉危险。'
             '形状不对一律拒绝，不许返回任何能被当成有数据的东西'},
    {'id': 'unregistered_aggregate_is_caught',
     'text': 'evidence 里出现既不在白名单也不在登记表里的字段，必须被报出来；'
             '这条判定是正向扫描，不靠字段名字'},
    {'id': 'aggregates_have_detail_and_constraint',
     'text': '每个聚合字段（strength / corroborated / primary_action / weakest_strength）'
             '都必须在 AGGREGATE_FIELDS 里登记明细字段和 must_not，否则测试会红'},
    {'id': 'aggregate_detail_fields_exist_in_output',
     'text': '聚合字段对应的明细字段必须真的出现在输出里，不能只写文档'},
    {'id': 'baseline_schema',
     'text': '基线文件自带 schema 号；对不上就拒绝，不静默按旧口径比'},
    {'id': 'baseline_error_carries_next_step',
     'text': '基线被拒绝时，错误信息里必须带重写和比较的两条命令'},
    {'id': 'unknown_is_null',
     'text': '未知写 null，不写 0；0 会被读成「查过，没有」'},
]

CONFIDENCE_SEMANTICS = {
    'what_strength_means': '复核成本和依赖复杂度，不是「这条有多可信」的概率',
    'why': '查表查出来的名字和逐字写着的名字，确定性上没有差别；'
           '差的是复核要看一处还是两处，以及结果依赖全包常量表的作用域规则。',
    'not_a_probability': True,
    'labels_not_buckets': '六层是标签，互相重叠；不可以相加或相减当总数。'
                          '唯一能当总数的是 unique_names，它是去重后的名字数。',
    'independence': {
        'table': INDEPENDENCE_TABLE,
        'sources': list(ALL_SOURCES),
        'rule': '独立性按两两组合查表判定，不留没点名的缝隙。'
                '静态来源之间（literal / literal-resolved / computed / harvested）共享同一份源码，'
                '不算独立；运行时与任一静态来源算独立。'
                '每个名字的 corroboration 已经按这张表算好，下游不必自己推导。',
    },
    'corroborated_rule': '至少两条独立见证才叫对上；对上之后强度取该名字所有来源里最高的那条，'
                         '不累加，也不因为对上就跳档。',
    'action_rule': '每个名字的 actions 列出它所有适用动作，primary_action 取其中最严格的一个'
                   '（顺序：cite < spot_check_source < trust_after_setup < read_code < triage）。'
                   '报告给的是最低保证，所以按最费事的那条走，下游不必再自己比。',
    'corroborated_is_not_uniform':
        'corroborated 只说明两条路互不依赖，不说明两条路都硬。'
        'computed+runtime 和 literal-resolved+runtime 都算对上，'
        '但前者静态那一侧本身就是需要人工看的低强度来源。'
        '看 strength_by_source 和 weakest_sources，别把「对上」当成均质的强证据集合。',
    'strength_vs_weakest':
        'strength 回答「这条记录里最好的证据有多硬」，'
        'weakest_sources / weakest_strength 回答「这条记录里最薄的环节有多薄」。'
        '两个问题不同，不能互相替代：只看 strength 会漏掉一条 0.9 的记录里还挂着 0.2 的来源。',
    'weakest_sources_semantics':
        'weakest_sources 是列表，并列最弱时全部列出，不任取其一；'
        'weakest_strength 是那个最弱的分值本身。',
    'must_not_semantics':
        'must_not 表示「工具声明了这条禁令，并且它有出处」，'
        '不表示「工具能检测消费方有没有遵守」。工具负责声明，消费方负责执行。'
        '看到 must_not 请当成一条要自己守的规矩，不是一道会拦住你的闸门。',
    'aggregate_rule':
        '聚合字段的判定是正向扫描：evidence 里出现一个既不在 EVIDENCE_FIELDS 白名单、'
        '也不在 AGGREGATE_FIELDS 登记表里的字段，就当成疑似聚合字段报出来。'
        '不靠字段名，也不靠人记得去登记。',
    'corroboration_kinds': CORROBORATION_KINDS,
    'compat_rule': {
        'bump_schema_when': [
            '字段改名或删除',
            '枚举取值增减或含义变化（例如 poke 的档位、sources 的取值）',
            'strength 的分值或语义变化',
            'limits / confidence 这类数组的结构变化',
            '名字的去重口径变化（unique_names 定义变化）',
        ],
        'no_bump_when': [
            '只新增字段且旧字段不动',
            '只改文案不改含义',
        ],
        'note': '换号只保证下游能察觉不兼容，不保证向下兼容；'
                '消费方应当按 schema 号选择解析逻辑，别只看字段在不在。',
    },
    'usage_constraints': [
        {
            'id': 'no_single_layer',
            'text': '任何一层都不该被单独引用；这是地图，不是判决书。',
            'must_not': ['use_layer_in_isolation'],
            'instead': '按 evidence 里每个名字的 sources 全体来看',
        },
        {
            'id': 'judge_by_all_sources',
            'text': '判断一个名字，要看它的全部来源标签，不要只挑最硬的那条。',
            'must_not': ['cherry_pick_strongest_source'],
            'instead': '用 primary_action 决定复核动作，用 sources 决定怎么读',
        },
        {
            'id': 'unknown_is_not_absent',
            'text': '「没看见」是未知，不能当成「没有」。',
            'must_not': ['treat_absent_as_negative'],
            'instead': '在 limits 里找这一路的盲点',
        },
        {
            'id': 'strength_is_not_risk',
            'text': 'strength 用来排序复核顺序，不用来当风险分值。',
            'must_not': ['score_risk_from_strength'],
            'instead': '风险判断看 poke 分档和 preload 暴露面',
        },
        {
            'id': 'primary_action_is_not_whole',
            'text': 'primary_action 只是「先做哪件事」，不能替代 actions。'
                    '只看主动作会丢掉「这条还同时有低保证来源」这件事，'
                    '和拆层单用是同一个错，只是发生在字段级。',
            'must_not': ['use_primary_action_alone', 'drop_lower_guarantee_sources'],
            'instead': '用 primary_action 决定先干什么，用 actions 和 sources 决定这条到底有多稳',
        },
        {
            'id': 'strength_alone_is_not_enough',
            'text': 'strength 是「最好的那条有多硬」，不是这条记录的整体硬度。'
                    '一条 0.9 的记录里可能挂着 0.2 的来源。',
            'must_not': ['use_strength_alone'],
            'instead': '同时看 strength_by_source，或直接看 weakest_sources',
        },
        {
            'id': 'corroborated_is_not_uniform',
            'text': 'corroborated 说明两条路互不依赖，不说明两条路都硬。',
            'must_not': ['use_corroborated_as_uniform'],
            'instead': '看 strength_by_source 里每一侧各自多少',
        },
        {
            'id': 'weakest_needs_the_list',
            'text': 'weakest_strength 只是一个分，并列最弱时是谁得看 weakest_sources。',
            'must_not': ['use_weakest_without_list'],
            'instead': '用 weakest_sources 拿到全部最弱来源',
        },
        {
            'id': 'meta_test_green_is_not_verified',
            'text': 'meta-test 绿了只代表「每条规则都有用例」，不代表「用例真的在测那条规则」。'
                    '一条用例可以挂在规则名下、断言却和规则无关，照样绿。'
                    '它防的是缺用例，不防用例无效。',
            'must_not': ['treat_meta_test_green_as_rule_verified'],
            'instead': '抽查用例断言的内容，或者让用例里带上规则自己的数据',
        },
        {
            'id': 'check_schema_before_parse',
            'text': '消费方必须先校验 schema 号，不匹配就拒绝解析，别按字段在不在猜。'
                    '换号只保证你能察觉不兼容，察觉与否取决于你有没有看。',
            'must_not': ['parse_without_schema_check'],
            'instead': '按 schema 号选择解析器，不认识就停下',
        },
    ],
}
# 每个来源对应一个动作；一个名字有多个来源时，取最严格的那个动作。
# 「严格」= 复核成本更高。报告给的是最低保证，所以按最费事的那条走。
ACTION_BY_SOURCE = {
    'literal': 'cite',
    'literal-resolved': 'spot_check_source',
    'runtime': 'trust_after_setup',
    'computed': 'read_code',
    'harvested': 'triage',
}
ACTION_STRICTNESS = ['cite', 'spot_check_source', 'trust_after_setup', 'read_code', 'triage']


SOURCE_STRENGTH = {
    'literal': 1.0,
    'literal-resolved': 0.9,
    'runtime': 0.8,
    'computed': 0.3,
    'harvested': 0.2,
}


def channel_sources(facts, probe=None):
    """每条通道名各自是被谁看见的。

    一层给整份报告定强度，还不够——同一个包里，有的名字是写死的，
    有的只在运行时见过，混在一起就会互相借光。这条函数按名字拆开记来源。
    """
    seen = {}

    def add(name, source, strength, where=None):
        item = seen.setdefault(name, {'sources': [], 'strength': 0.0, 'where': None})
        if source not in item['sources']:
            item['sources'].append(source)
        if strength > item['strength']:
            item['strength'] = strength
        if where and not item['where']:
            item['where'] = where

    for name, where in facts['handlers'] + facts['invokes'] + facts['exposes']:
        if name in facts.get('resolved', ()):
            # 名字是靠还原推出来的，不是逐字写在那儿，强度低一档
            add(name, 'literal-resolved', 0.9, where)
        else:
            add(name, 'literal', 1.0, where)
    if probe and not probe.get('error'):
        for name in probe.get('handlers') or []:
            add(name, 'runtime', 0.8)
        for name in probe.get('listeners') or []:
            add(name, 'runtime', 0.8)
    for what, where in facts['dynamic']:
        add(what, 'computed', 0.3, where)
    for name, value in (facts.get('harvested') or {}).items():
        where = value[0] if isinstance(value, tuple) and value else None
        add(name, 'harvested', 0.2, where)

    for item in seen.values():
        item['sources'] = sorted(item['sources'])
        # 一个名字可能有多个来源，动作按最严格的那个给，别让人猜听谁的
        actions = [ACTION_BY_SOURCE[s] for s in item['sources'] if s in ACTION_BY_SOURCE]
        item['actions'] = sorted(set(actions), key=ACTION_STRICTNESS.index)
        item['primary_action'] = max(actions, key=ACTION_STRICTNESS.index) if actions else 'review'
        # 对上要分种类：按判定表数一数，有没有一对是互不依赖的
        srcs = item['sources']
        pairs = [(a, b) for i, a in enumerate(srcs) for b in srcs[i + 1:]]
        has_independent = any(independent(a, b) for a, b in pairs)
        static_sources = {'literal', 'literal-resolved', 'computed', 'harvested'} & set(srcs)
        if has_independent:
            item['corroboration'] = 'static_runtime'
        elif len(static_sources) >= 2:
            item['corroboration'] = 'static_static'
        else:
            item['corroboration'] = 'none'
        item['corroborated'] = item['corroboration'] == 'static_runtime'
        # 「对上」只说明两条路互不依赖，不说明两条路都硬。
        # 把每一侧的硬度也带上，免得一个布尔把差异盖掉。
        item['strength_by_source'] = {s: SOURCE_STRENGTH.get(s, 0.0) for s in item['sources']}
        # 最弱可能不止一个，用列表；字段名要是单数，读的人会以为只有一个
        lowest = min(item['strength_by_source'].values())
        item['weakest_sources'] = sorted(s for s, v in item['strength_by_source'].items()
                                         if v == lowest)
        item['weakest_strength'] = lowest
        item['independent_pairs'] = ['%s+%s' % (a, b) for a, b in pairs if independent(a, b)]
    return seen


def confidence_levels(facts, probe=None, poke=None):
    """这份报告里每一样东西，各自能证明到什么程度。

    人看容易把不同强度的话当成一样重；机器读更容易——它只会被字段名骗。
    所以这一层既给人看，也直接进 JSON：强度用数字，未知用 null，不用 0 顶替。
    """
    literal = len(facts['handlers']) + len(facts['invokes']) + len(facts['exposes'])
    resolved_names = set(facts.get('resolved') or ())
    literal_resolved = sum(
        1 for name, _where in facts['handlers'] + facts['invokes'] + facts['exposes']
        if name in resolved_names)
    literal_direct = literal - literal_resolved
    harvested = facts.get('harvested') or {}
    own = sum(1 for value in harvested.values()
              if isinstance(value, tuple) and len(value) == 2 and value[1] == 'self')

    sources = channel_sources(facts, probe=probe)
    corroborated_items = [item for item in sources.values() if item['corroborated']]
    corroborated = len(corroborated_items)
    corroborated_strength = max((item['strength'] for item in corroborated_items), default=0.0)

    levels = []
    if corroborated:
        levels.append({
            'id': 'corroborated',
            'label': '两条路都对上的',
            'count': corroborated,
            'unit': '条',
            'strength': corroborated_strength,
            'can_prove': '静态和运行时各看见一次，两条路互不依赖',
            'cannot_prove': '对上的是名字，不是行为；门后逻辑仍然没审',
            'next_step': '优先看这几条，它们最不像我编的',
        })
    levels.append({
        'id': 'literal',
        'label': '写死的名字',
        'count': literal_direct,
        'unit': '条',
        'strength': 1.0,
        'can_prove': '源码里逐字写着，file:line 能回到原文复核',
        'cannot_prove': '只覆盖写死的写法；拼出来的、算出来的它看不见',
        'next_step': '直接引用，但别当成完整清单',
    })
    if literal_resolved:
        levels.append({
            'id': 'literal-resolved',
            'label': '靠还原才认出的',
            'count': literal_resolved,
            'unit': '条',
            'strength': 0.9,
            'can_prove': '名字是从本包的字符串池、常量或常量对象里查出来的，原始出处还在源码里',
            'cannot_prove': '查得出不等于它真是通道；表可能被覆盖、字段可能同名不同义',
            'next_step': '能和运行时对上一个就更硬；对不上要回原文看那张表',
        })

    if probe and not probe.get('error'):
        levels.append({
            'id': 'runtime',
            'label': '程序自己报的',
            'count': len(probe.get('handlers') or []),
            'windows': len(probe.get('windows') or []),
            'unit': '条通道',
            'strength': 0.8,
            'can_prove': '探针连上主进程，直接读它注册了什么，不是猜的',
            'cannot_prove': '依赖它肯启动；启动配方每个应用不一样，换包要重摸',
            'next_step': '换另一个包先确认能起来，再信这一层',
        })
    elif probe:
        levels.append({
            'id': 'runtime',
            'label': '程序自己报的',
            'count': 0,
            'unit': '条通道',
            'strength': 0.0,
            'can_prove': '无——探针没跑通',
            'cannot_prove': '应用有没有通道，这一层什么都没说',
            'next_step': '先解决启动，再谈运行时',
        })

    if poke:
        levels.append({
            'id': 'poke',
            'label': '敲过一遍的',
            'count': None,
            'unit': '见分档',
            'strength': 0.6,
            'can_prove': '喂过不合规输入，看它是照收还是拒绝',
            'cannot_prove': '拒绝只证明有门；门后逻辑没审，参数校验仍然未知',
            'next_step': '被拦下的一档当「有门」用，另一档回去看代码',
        })

    levels.append({
        'id': 'computed',
        'label': '名字是算出来的',
        'count': len(facts['dynamic']),
        'unit': '处',
        'strength': 0.3,
        'can_prove': '知道这里有调用，名字不是写死的',
        'cannot_prove': '名字是什么，算不出来',
        'next_step': '人工看，这是研判的第一入口',
    })
    levels.append({
        'id': 'harvested',
        'label': '打捞出来的候选',
        'count': len(harvested),
        'own_count': own,
        'unit': '个',
        'strength': 0.2,
        'can_prove': '这些字符串长得像通道名',
        'cannot_prove': '长得像不等于就是；当线索用，别当结论',
        'next_step': '拿真名去比对，或者运行时验证',
    })
    levels.append({
        'id': 'unseen',
        'label': '没看见的',
        'count': None,
        'unit': '',
        'strength': 0.0,
        'can_prove': '无',
        'cannot_prove': '我这条路看不见，不代表它不在',
        'next_step': '换 REA 走语法级，或者运行时探针',
    })
    # 每层配一个机器能照做的动作，别只给一句人话
    layer_action = {
        'corroborated': 'cite_with_caveat',
        'literal': 'cite',
        'literal-resolved': 'spot_check_source',
        'runtime': 'trust_after_setup',
        'poke': 'review_handler',
        'computed': 'read_code',
        'harvested': 'triage',
        'unseen': 'escalate',
    }
    for level in levels:
        level['action'] = layer_action.get(level['id'], 'review')
    return levels


def runtime_crosscheck(probe, static_names):
    """静态和运行时各看见了什么，差在哪儿。给人看的那段和 json 共用这一份。"""
    if not probe:
        return None
    if probe.get('error'):
        return {'error': probe.get('error'), 'handlers': [], 'listeners': [],
                'windows': [], 'only_runtime': [], 'only_static': sorted(static_names)}
    handlers = probe.get('handlers') or []
    only_runtime = sorted(set(handlers) - set(static_names))
    only_static = sorted(set(static_names) - set(handlers))
    return {
        'handlers': handlers,
        'listeners': probe.get('listeners') or [],
        'windows': probe.get('windows') or [],
        'only_runtime': only_runtime,
        'only_static': only_static,
    }


def strength_notes(facts, probe=None, confidence=None):
    """该包上的话说清楚：最高强度是哪一档、有没有空层。"""
    notes = []
    resolved_names = set(facts.get('resolved') or ())
    total = len(facts['handlers']) + len(facts['invokes']) + len(facts['exposes'])
    direct = sum(1 for name, _w in facts['handlers'] + facts['invokes'] + facts['exposes']
                 if name not in resolved_names)
    if total and not direct:
        notes.append(f'这包上 {total} 条字面通道全是查表查出来的，一条都没逐字写在调用点上；'
                     '"写死的名字"这一层（强度 1.0）是空的，本报告能给出的最高强度是 0.9')
    elif total:
        notes.append(f'字面通道 {total} 条：逐字写着的 {direct} 条，查表得来的 {total - direct} 条')
    return notes


def blind_spots(facts, probe=None, poke=None):
    """这份报告看不到的地方。和 md 那节「没看清的地方」是同一份清单。"""
    items = ['混淆过、压过、名字算出来的代码，我一条都认不出来；所以「没看见」永远是未知，不是没有']
    if facts['obfuscation']:
        items.append(f"这包有 {len(facts['obfuscation'])} 处混淆指纹，"
                     f"其中强 {sum(1 for _n, _w, l in facts['obfuscation'] if l == 'strong')} 处")
    if facts['native_files']:
        items.append(f"有 {len(facts['native_files'])} 个原生模块，越界和内存问题不在这一层看")
    items.append('注册过、能调，不等于调得成；权限和 sender 校验要看运行时那一层')
    items.extend(strength_notes(facts, probe=probe))
    if not probe:
        items.append('没有给 --runtime，运行时那层是空的')
    if not poke:
        items.append('没有给 --poke，门禁状态全部未知')
    return items


def confidence_ladder(facts, probe=None, poke=None):
    """把 confidence_levels 排成一张给人看的表。"""
    levels = confidence_levels(facts, probe=probe, poke=poke)

    def amount(level):
        count = level['count']
        if count is None:
            return '未知' if level['id'] == 'unseen' else level.get('unit') or '—'
        text = f"{count} {level.get('unit', '')}".strip()
        if level.get('own_count') is not None:
            text += f"，其中 {level['own_count']} 个是它自己写的"
        if level.get('windows') is not None:
            text += f" / {level['windows']} 个窗口"
        return text

    out = ['', '### 可信度分层', '',
           '同一条报告里的话，强度不是一样的。从上往下，越靠上越站得住。',
           '这张表也原样进了 `--format json` 的 `confidence` 字段，机器读同一套。', '']
    out.append('| 这一层 | 有多少 | 能证明什么 | 不能证明什么 / 下一步 |')
    out.append('| --- | --- | --- | --- |')
    for level in levels:
        out.append(f"| {level['label']} | {amount(level)} | "
                   f"{level['can_prove']} | {level['cannot_prove']}；{level['next_step']} |")
    out.append('')
    out.append('> 这张表里的任何一层都不该被单独引用。报告是给人做判断用的地图，不是判决书。')
    out.append('> 每层会重叠——同一个名字可能既靠还原查出来，又被运行时看见，两行都会算它。')
    out.append('> 所以别把这一列加起来当总数，它不是分类，是几张不同的标签。')
    out.append('> 每个名字各自的来源记在 JSON 的 `evidence` 里——一个包里，写死的名字和')
    out.append('> 只在运行时见过的名字不是一回事，混在一起会互相借光。')
    out.append('')
    return out


def baseline_delta(facts, baseline):
    """跟上次比，多了什么、少了什么、哪里变了。

    基线不只看发现，也看通道名——一个包升级之后新开一扇门，
    那是比「多一条可疑项」更要紧的事。
    """
    old_channels = set(baseline.get('channels') or ())
    new_channels = set(facts.get('channels') or ())
    old_findings = {(text, where) for _l, text, where in baseline.get('findings') or ()}
    new_findings = [f for f in audit_asar(facts) if (f[1], f[2]) not in old_findings]
    return {
        'added_channels': sorted(new_channels - old_channels),
        'removed_channels': sorted(old_channels - new_channels),
        'new_findings': new_findings,
        'baseline_channels': len(old_channels),
    }


def render_baseline(delta):
    out = ['', '## 跟基线比', '']
    if not delta['baseline_channels'] and not delta['new_findings']:
        out.append('- 基线是空的，等于是第一次跑。这次的结果已经可以当基线用')
        out.append('')
        return out
    out.append(f"- 基线里有 {delta['baseline_channels']} 条通道")
    added, removed = delta['added_channels'], delta['removed_channels']
    if added:
        out.append(f'- 新冒出来 {len(added)} 条：')
        for name in added[:12]:
            out.append(f'  - `{name}`')
        if len(added) > 12:
            out.append(f'  - 还有 {len(added) - 12} 条')
    else:
        out.append('- 没有新通道')
    if removed:
        out.append(f'- 基线里有、这次没了的 {len(removed)} 条：')
        for name in removed[:12]:
            out.append(f'  - `{name}`')
        if len(removed) > 12:
            out.append(f'  - 还有 {len(removed) - 12} 条')
        out.append('> 名字没了可能是删了，也可能是换了写法认不出——这个工具分不开这两件事。')
    out.append('')
    return out


def build_asar_report(target, facts, file_count, total_bytes, names, evidence,
                      checks, poke_buckets, baseline_obj):
    """asar 路径的 JSON 报告。单独抽出来，好让契约测试直接盯它的顶层键。"""
    return {
        'schema': 'ipcsurface/asar/10',
        'mode': 'asar',
        'subject': target,
        'files': file_count,
        'bytes': total_bytes,
        'unique_names': len(evidence),
        'channels': sorted(names),
        'dynamic': [what for what, _ in facts['dynamic']],
        'exposes': [n for n, _ in facts['exposes']],
        'web_preferences': {k: v[0] for k, v in facts['prefs'].items()},
        'native_files': facts['native_files'],
        'obfuscation': [{'what': n, 'where': w, 'level': l}
                        for n, w, l in facts['obfuscation']],
        'confidence': confidence_levels(facts),
        'confidence_semantics': CONFIDENCE_SEMANTICS,
        'evidence': evidence,
        'runtime': checks,
        'poke': None if poke_buckets is None else {
            'channels': poke_buckets['channels'],
            'swallowed': poke_buckets['swallowed'],
            'gated': poke_buckets['gated'],
            'unknown': poke_buckets['unknown'],
        },
        'limits': blind_spots(facts),
        'baseline': baseline_obj,
        'version': __version__,
    }


def render_asar(target, facts, file_count, total_bytes, show_all=False, findings=None,
                probe=None, poke=None, baseline=None):
    out = ['# Electron 能力面清单（粗扫）', '']
    out.append(f'- 目标：`{os.path.abspath(target)}`')
    out.append(f'- {file_count} 个文件，{total_bytes / 1024 / 1024:.1f} MB，其中 {facts["scanned"]} 个提到 IPC')
    out.append(f'- {stamp()}')
    out.append('')
    out.append('## 这份报告能信多少')
    out.append('')
    out.append('这是字符串级粗扫：只认写死在源码里的名字，不建语法树，跟着代码走不通。')
    out.append('要准的，先跑 `rea analyze-javascript-application`，再把 Evidence 喂给本工具。')
    strong = [h for h in facts['obfuscation'] if h[2] == 'strong']
    weak = [h for h in facts['obfuscation'] if h[2] == 'weak']
    if strong:
        out.append('')
        out.append('这包动过手脚。下面的名字可能只是一部分，别拿它当完整清单。')
    out.append('')
    out.extend(confidence_ladder(facts, probe=probe, poke=poke))
    if baseline is not None:
        out.extend(render_baseline(baseline_delta(facts, baseline)))

    # 一条都没扫到的时候，最容易被读成「这包干净」。
    # 那是我这套办法的空白，不是这包的结论，得顶在最前面说清楚。
    if not (facts['exposes'] or facts['handlers'] or facts['invokes']):
        harvested = facts.get('harvested') or {}
        own = sum(1 for _where, kind in harvested.values() if kind == 'self')
        blocked = []
        if facts['obfuscation']:
            blocked.append(f'混淆痕迹 {len(facts["obfuscation"])} 处')
        if facts['dynamic']:
            blocked.append(f'名字是拼出来的 {len(facts["dynamic"])} 处')
        if harvested:
            blocked.append(f'打捞兜底只捞到 {len(harvested)} 个候选，其中 {own} 个是这个应用自己写的')
        out.append('## 一条字面通道都没看见')
        out.append('')
        out.append('先别读成「这个包里没有」。这句的意思是：我这条路走不通。')
        out.append('粗扫只认写死的名字。名字是拼出来的、从别处算出来的、或者整个文件被压过，我一律看不见。')
        out.append('')
        if blocked:
            out.append('这次实际卡住的地方：')
            for line in blocked:
                out.append(f'- {line}')
        else:
            out.append('这次连混淆和拼接都没认出来——更可能是我认不出它的写法，不是它简单。')
        out.append('')
        out.append('所以这份报告对「有没有通道」这个问题，答案是「不知道」。')
        out.append('想拿到答案只有两条路：跑一遍 REA 走语法级，或者把打捞出来的候选一条条自己看。')
        out.append('')

    if facts['obfuscation']:
        out.append('## 混淆痕迹')
        out.append('')
        out.append('解不开，但认得出。强的那几条说明代码被处理过；弱的多半只是库的写法。')
        out.append('')
        shown = (strong + weak) if show_all else (strong + weak)[:8]
        for name, where, level in shown:
            tag = '强' if level == 'strong' else '弱'
            out.append(f'- [{tag}] {name}  `{where}`')
        rest = len(facts['obfuscation']) - len(shown)
        if rest > 0:
            out.append(f'- 还有 {rest} 处没列，加 `--all` 看全')
        out.append('')
        out.append('> 一个两万文件的包里 `new Function` 出现几十次是常态，那不是混淆。')

    if facts.get('recovered'):
        out.append('## 从 sourcemap 翻回来的')
        out.append('')
        out.append(f'包里带着 {len(facts["recovered"])} 份没压过的源码，上面有几行是从它们里扫到的：')
        out.append('')
        for rel in facts['recovered'][:6]:
            out.append(f'- `{rel}`')
        if len(facts['recovered']) > 6:
            out.append(f'- 还有 {len(facts["recovered"]) - 6} 份')
        out.append('')
        out.append('> 这是这包自己把源码交出来的，不是猜的。')
        out.append('')

    out.append('## 窗口设置')
    if facts['prefs']:
        for key, (value, where) in sorted(facts['prefs'].items()):
            out.append(f'- `{key}` = {value}  `{where}`')
    else:
        out.append('- 没扫到 webPreferences，可能压根不是 Electron，也可能写得绕')
    for value, where in facts['preloads']:
        out.append(f'- preload = `{value}`  `{where}`')
    for key in ('nodeIntegration', 'contextIsolation', 'sandbox'):
        if key not in facts['prefs']:
            out.append(f'- 没扫到 `{key}`，可能是默认值，也可能在别处写')
    out.append('')

    out.append('## preload 挂出去的名字')
    if facts['exposes']:
        for value, where in facts['exposes']:
            out.append(f'- `window.{value}`  `{where}`')
    else:
        out.append('- 没扫到 contextBridge.exposeInMainWorld')
    out.append('')

    out.append('## 通道')
    out.append('')
    out.append('| 通道 | 主进程 | 页面侧 |')
    out.append('| --- | --- | --- |')
    names = sorted({n for n, _ in facts['handlers']} | {n for n, _ in facts['invokes']})
    host = defaultdict(list)
    page = defaultdict(list)
    limit = len(names) if show_all else 30
    for name, where in facts['handlers']:
        host[name].append(where)
    for name, where in facts['invokes']:
        page[name].append(where)
    for name in names[:limit]:
        h = ', '.join(f'`{w}`' for w in host.get(name) or ['—'])
        p = ', '.join(f'`{w}`' for w in page.get(name) or ['—'])
        out.append(f'| `{name}` | {h} | {p} |')
    if not names:
        out.append('| — | — | — |')
    elif len(names) > limit:
        out.append(f'| … 还有 {len(names) - limit} 条没列 | 加 `--all` 看全 | |')
    out.append('')
    if len(names) > 12:
        groups = defaultdict(int)
        for name in names:
            groups[re.split(r'[:/.]', name)[0] or name] += 1
        out.append('按前缀分组：' + '，'.join(f'`{k}` {v} 条' for k, v in
                                            sorted(groups.items(), key=lambda kv: -kv[1])[:8]))
        out.append('')

    harvested = facts.get('harvested') or {}
    if harvested:
        mine = {k: v for k, v in harvested.items() if v[1] == 'self'}
        others = {k: v for k, v in harvested.items() if v[1] != 'self'}
        out.append('## 长得像通道的字符串')
        out.append('')
        out.append(f'调用点认不出了，但名字本身还躺在字符串里。捞上来 {len(harvested)} 个，'
                   f'其中 {len(mine)} 个是这个应用自己写的：')
        out.append('')
        for value in sorted(mine)[:20]:
            out.append(f'- `{value}`  `{mine[value][0]}`')
        if len(mine) > 20:
            out.append(f'- 还有 {len(mine) - 20} 个自己的')
        if others:
            out.append('')
            out.append(f'另外 {len(others)} 个在第三方库和测试里，噪音大，先折起来：')
            out.append('')
            for value in sorted(others)[:5]:
                out.append(f'- `{value}`  `{others[value][0]}`')
            if len(others) > 5:
                out.append(f'- 还有 {len(others) - 5} 个，加 `--all` 看全')
        out.append('')
        out.append('> 这些只保证「长得像 `前缀:名字`」，不保证是通道。一个个去代码里搜，比从零翻快得多。')
        out.append('')

    out.append('## 没看清的地方')
    out.append('')
    out.append('这张表只能证明哪些看清了，不能证明没有什么。')
    out.append('')
    if facts['native_files']:
        out.append(f"- 这包带着 {len(facts['native_files'])} 个 native 模块，越界、泄漏只可能在它们里面：")
        for rel in facts['native_files'][:8]:
            out.append(f"  - `{rel}`")
        out.append('- 上面那张表跟它们没关系，两边得分开查')
    else:
        out.append('- 没有 native 模块，越界这类本来就不该出在 JS 这层')
    if facts.get('nested_asar'):
        out.append(f"- 里面有 {len(facts['nested_asar'])} 个套着的 asar，这一层没拆开看：")
        for rel in facts['nested_asar'][:5]:
            out.append(f"  - `{rel}`")
        out.append('- 要看得先把它们解出来，单独跑一遍')
    if facts['dynamic']:
        for what, where in facts['dynamic'][:20]:
            out.append(f'- 名字是算出来的不是写死的：`{what}`  `{where}`')
    else:
        out.append('- 没扫到算出来的通道名；但不等于没有，字符串拼法有无数种')
    out.append('- 混淆过、压过的代码，这里一条都认不出来')
    out.append('- 内存层面不看，越界、泄漏要在运行时或者 native 那边查')
    out.append('')
    out.append('> 粗扫只用来决定要不要认真查，不用来签字。')
    if findings:
        out.append('')
        out.append('## 可疑项')
        order = {'high': 0, 'medium': 1}
        for level, text, where in sorted(findings, key=lambda f: order.get(f[0], 9))[:10]:
            out.append(f'- [{level}] {text}  `{where}`')
    return '\n'.join(out)


# ---------------------------------------------------------------- evidence

def load_record(path):
    try:
        with open(path, encoding='utf-8-sig') as fh:
            data = json.load(fh)
    except UnicodeDecodeError:
        raise SystemExit(f'读不了这个文件，它不是文本：{path}\n'
                         '要分析应用就给 .asar，要分析模块给 .exe 或 .dll')
    except json.JSONDecodeError:
        raise SystemExit(f'这不是 REA 的 Evidence：{path}\n'
                         '要么直接给 .asar / .exe / .dll，要么先跑一遍\n'
                         '  rea analyze-javascript-application app.asar --detail summary --evidence_output ev')
    if isinstance(data, dict) and 'records' in data:
        records = data['records']
    elif isinstance(data, list):
        records = data
    else:
        raise SystemExit('这不是 REA 的 Evidence 包：找不到 records')
    for record in records:
        result = record.get('normalized_result') or {}
        if 'graph' in result:
            return result
    raise SystemExit('证据里没有应用图，可能不是 analyze-javascript-application 的输出')


def loc(evidence):
    value = ((evidence or {}).get('location') or {}).get('value') or {}
    if value.get('kind') == 'source-range':
        return f"{value['source']}:{value['start']['line'] + 1}"
    if value.get('kind') == 'artifact-path':
        return value.get('path', '?')
    return '?'


# 输入的坏法是有类别的，不只是「读不动」。
# 下游要决定「重试还是放弃」，得看类别，不能去解析中文文案。
# 报告 JSON 的顶层键白名单。多一个键就红——「别把 durable 写进报告」这条
# 纪律不能只写在 README 里，得有个东西替我们盯着。
REPORT_TOP_LEVEL_KEYS = frozenset({
    'schema', 'version', 'mode', 'subject', 'files', 'bytes',
    'channels', 'exposes', 'dynamic', 'native_files', 'obfuscation',
    'unique_names', 'evidence', 'confidence', 'confidence_semantics',
    'limits', 'runtime', 'poke', 'web_preferences', 'baseline',
})


def numbered_sections(headings):
    """找出带编号的章节标题（`## 1. xxx` / `## 12 xxx`）。

    md 报告现在不带编号；一旦有人加了，这个函数会返回非空，
    守卫用例就会红——红的时候它自己说明「不是回归，是前提变了」。
    """
    found = []
    for heading in headings:
        parts = heading.split()
        if len(parts) >= 2 and parts[1][0].isdigit():
            found.append(heading)
    return found


def check_report_keys(report):
    """报告顶层键必须在白名单里。返回 (多出来的, 少了的)。"""
    keys = set(report)
    return sorted(keys - REPORT_TOP_LEVEL_KEYS), sorted(REPORT_TOP_LEVEL_KEYS - keys)


INPUT_ERROR_KINDS = {
    'file_missing': '文件不存在或者没权限',
    'encoding_invalid': '不是 UTF-8',
    'empty_input': '空文件',
    'json_malformed': '不是合法 JSON',
    'json_truncated': 'JSON 被截断（括号/引号没闭合）',
    'depth_exceeded': '嵌套层数超过上限',
    'shape_invalid': 'JSON 合法但形状不对',
}

# 显式上限。靠 RecursionError 兜底是不稳的：不同 Python、不同栈大小行为会漂移，
# 回归用例在新环境里未必复现得出。所以在解析之前先把层数数一遍，超了直接拒。
MAX_JSON_DEPTH = 64


class InputError(SystemExit):
    """带类别的输入错误。文案给人看，kind 给程序看。"""

    def __init__(self, kind, message):
        super().__init__(message + '\nkind: ' + kind)
        self.kind = kind


def json_depth(text):
    """数一数这份 JSON 最深套了几层。字符串里的括号不算。"""
    depth = 0
    deepest = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in '[{':
            depth += 1
            if depth > deepest:
                deepest = depth
        elif char in ']}':
            depth -= 1
            if depth < 0:
                return deepest
    return deepest


WRITE_TMP_PREFIX = '.ipcsurface-'
_windows_hint_shown = False
_unknown_note_shown = False
STALE_BACKUP_SECONDS = 24 * 3600
FAILED_KEEP_SECONDS = 6 * 3600   # 诊断现场比副本短：价值随时间衰减，敏感留存不衰减

# 写出去的坏法也得有类别。磁盘满、没权限、写了一半，都要说清是哪一种。
OUTPUT_ERROR_KINDS = {
    'disk_full': '磁盘满了',
    'permission_denied': '没有写权限',
    'path_missing': '目标目录不存在',
    'short_write': '写完的字节数和该写的对不上',
    'invalid_json_output': '声明是 JSON，但写出来的东西解析不了',
    'write_failed': '写入失败',
    'replace_failed': '替换不上去，目标可能被占用',
    'symlink_target': '目标路径是符号链接，备份与替换语义不一致',
}


def _digest(path):
    """算一遍文件的指纹。写完读回来比对，才知道落盘的是不是我们写的那份。"""
    sha = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(65536), b''):
            sha.update(chunk)
    return sha.hexdigest()


class OutputError(SystemExit):
    """带类别的输出错误。写不完就别留半成品。"""

    def __init__(self, kind, message):
        super().__init__(message + '\nkind: ' + kind)
        self.kind = kind


def _output_kind(exc):
    if exc.errno == errno.ENOSPC:
        return 'disk_full'
    if exc.errno in (errno.EACCES, errno.EPERM):
        return 'permission_denied'
    if exc.errno == errno.ENOENT:
        return 'path_missing'
    return 'write_failed'


class FsyncResult(enum.Enum):
    """目录刷盘这件事，有三种可能，不是两种。"""

    OK = 'ok'
    UNSUPPORTED = 'unsupported'   # 这套系统没有这个能力（Windows）
    FAILED = 'failed'


DURABLE_YES = 'yes'
DURABLE_NO = 'no'
DURABLE_UNKNOWN = 'unknown'


class WriteResult:
    """写完之后的事实。

    durable 是三态：yes / no / unknown。
    把「这套系统根本没法确认」报成 yes，就是拿不知道冒充知道——
    这个项目从第一天起反对的就是这件事。
    """

    def __init__(self, path, durable, warnings):
        self.path = path
        self.durable = durable              # 'yes' | 'no' | 'unknown'
        self.warnings = list(warnings)

    @property
    def durable_known(self):
        return self.durable != DURABLE_UNKNOWN

    def __repr__(self):
        return f'WriteResult(path={self.path!r}, durable={self.durable!r}, warnings={self.warnings})'


def _fsync_dir(directory):
    """替换之后刷一次目录，让 rename 真正落到盘上。返回 FsyncResult。

    UNSUPPORTED 不等于 FAILED：前者是「这套系统没这个能力」，后者是「有这能力但没成功」。
    混成一个 None/falsy，调用方迟早把未知当失败，或者把未知当成功。
    """
    if os.name == 'nt':
        return FsyncResult.UNSUPPORTED
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return FsyncResult.FAILED
    try:
        os.fsync(fd)
        return FsyncResult.OK
    except OSError:
        return FsyncResult.FAILED
    finally:
        os.close(fd)


def _backup_stamp(name):
    """从备份文件名里取出创建时间戳（毫秒）。取不到就返回 None。

    不用 ctime：Linux 上它是 inode 变更时间，Windows 上是创建时间，
    网络文件系统上更是各说各话。写进文件名里最稳，跨平台一个语义。
    """
    for part in reversed(name.split('.')):
        if part.isdigit() and len(part) >= 13:
            return int(part[:13])
    return None


def _backup_age(path):
    """副本有多旧，只看文件名。取不到时间戳就返回 None（当作未知，不删）。

    年龄判断的可靠性上限就是系统时钟的可靠性：NTP 校正、手改时间、快照恢复
    都会让时钟往回走。负年龄（副本「来自未来」）按「太新」处理，不删——
    宁可留着一个旧副本，也不能因为时钟抽风把不该删的删掉。
    """
    stamp = _backup_stamp(os.path.basename(path))
    if stamp is None:
        return None
    age = time.time() - stamp / 1000.0
    return age if age >= 0 else 0.0


def _ours(name, basename):
    """是不是我们自己生成的那种名字：.{basename}.{13位时间戳}.{8位hex}.{后缀}"""
    match = re.fullmatch(r'\.' + re.escape(basename) + r'\.(\d{13})\.([0-9a-f]{8})\.(bak|failed)', name)
    return match.group(1) if match else None


def clean_stale_backups(directory, basename, max_age=STALE_BACKUP_SECONDS):
    """清掉崩在中间留下的孤儿副本和诊断件，返回 (删掉的, 该提醒的)。

    - 只认自己生成的名字，用户手工放的 report.md.bak 不动，也不会被误报；
    - 删 .bak 之前先确认 target 还在（target 都没了，那份可能是唯一旧版）；
    - .failed 是诊断件，按同样年龄清，不无限攒。
    """
    removed = []
    kept = []
    target = os.path.join(directory, basename)
    try:
        names = os.listdir(directory)
    except OSError:
        return removed, kept
    target_ok = os.path.exists(target)
    now = time.time()
    for name in names:
        stamp = _ours(name, basename)
        if stamp is None:
            continue
        full = os.path.join(directory, name)
        suffix = name.rsplit('.', 1)[-1]
        age = now - int(stamp) / 1000.0
        try:
            # 顺序要紧：先看 target 在不在，再看年龄。
            # 反过来的话，时钟大幅前跳会让一批副本同时变成「过期候选」，
            # 只能靠逐个救回来——先判存在性就没有这个批量误删的窗口。
            if suffix == 'bak' and not target_ok:
                kept.append(full)      # 唯一的旧版，留着提醒
                continue
            limit = FAILED_KEEP_SECONDS if suffix == 'failed' else max_age
            if age <= limit:
                kept.append(full)
                continue
            os.unlink(full)
            removed.append(full)
        except OSError:
            kept.append(full)
    return removed, kept


def write_output(path, text, expect_json=False):
    """要么完整写出来，要么一个字节都不留。

    顺序：临时文件 → fsync → 核字节数 →（声明 JSON 就在 tmp 上解析一遍）
    → 复制旧版副本 → os.replace → 刷目录 → 删副本。

    替换之后不再核内容：os.replace 成功就说明 target 等于 tmp，再比一遍是恒真。

    返回 WriteResult，不是光返回路径：目录 fsync 失败时内容已经写进去了，
    只是崩溃后可能回退——这是个需要被看见的状态，不能压成一个「成功」。
    """
    if os.path.islink(path):
        raise OutputError(
            'symlink_target',
            f'这个路径是符号链接：{path}\n'
            '备份会跟随链接复制目标内容，而替换会把链接本身变成普通文件，两头语义不一样。\n'
            f'下一步：把真实路径 {os.path.realpath(path)} 传进来，别让工具替你猜。')

    directory = os.path.dirname(os.path.abspath(path)) or '.'
    basename = os.path.basename(path)
    try:
        os.makedirs(directory, exist_ok=True)
    except OSError as exc:
        raise OutputError(_output_kind(exc), f'目标目录建不出来：{directory}\n{exc}')

    warnings = []
    _removed, kept = clean_stale_backups(directory, basename)
    if kept:
        warnings.append(f'发现 {len(kept)} 个未处理的备份副本，可能是之前崩在中间留下的；'
                        f'没自动恢复，请人工确认（第一个：{kept[0]}）')

    handle, temp_path = tempfile.mkstemp(dir=directory, prefix=WRITE_TMP_PREFIX, suffix='.part')
    stamp = int(time.time() * 1000)
    backup = os.path.join(directory, f'.{basename}.{stamp}.{uuid.uuid4().hex[:8]}.bak')
    had_old = os.path.exists(path)
    failed_keep = os.path.join(directory, f'.{basename}.{stamp}.{uuid.uuid4().hex[:8]}.failed')
    try:
        with os.fdopen(handle, 'w', encoding='utf-8', newline='') as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())

        expected = len(text.encode('utf-8'))
        actual = os.path.getsize(temp_path)
        if actual != expected:
            raise OutputError('short_write',
                              f'写到一半：{path}\n应写 {expected} 字节，实际 {actual} 字节。'
                              '半份报告比没有更坏，已经删掉了。')

        if expect_json:
            try:
                with open(temp_path, encoding='utf-8') as fh:
                    json.load(fh)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise OutputError('invalid_json_output',
                                  f'声明是 JSON，但生成出来的东西解析不了：{path}\n{exc}\n'
                                  '临时文件已经删掉，原来的报告没动。')

        if had_old:
            try:
                shutil.copy2(path, backup)
            except OSError as exc:
                raise OutputError(_output_kind(exc),
                                  f'备份旧报告失败，所以没有替换：{path}\n{exc.strerror or exc}')

        try:
            os.replace(temp_path, path)
        except OSError as exc:
            # 这份 tmp 是「我们确实想写什么」的唯一现场，留着当诊断，改名 .failed
            try:
                os.replace(temp_path, failed_keep)
                kept_note = f'\n这次要写的内容留在 {failed_keep}，确认完可以删。'
            except OSError:
                kept_note = ''
            raise OutputError('replace_failed',
                              f'替换不上去：{path}\n{exc.strerror or exc}\n'
                              '目标可能被别的程序占用，关掉它再试一次。原报告没动。' + kept_note)

        fsync_state = _fsync_dir(directory)
        if fsync_state is FsyncResult.OK:
            durable = DURABLE_YES
        elif fsync_state is FsyncResult.FAILED:
            durable = DURABLE_NO
            warnings.append('内容已经替换，但目录 fsync 没成功：崩溃后这份报告可能回退到旧版。')
        elif fsync_state is FsyncResult.UNSUPPORTED:
            # 这套系统没法确认是不是落盘了。报 unknown：不阻塞，也不冒充知道。
            durable = DURABLE_UNKNOWN
            warnings.append('本平台不支持刷目录，无法确认持久性：文件已是新版，'
                            '崩溃后是否回退取决于文件系统。')

        else:
            raise AssertionError('未处理的 FsyncResult：' + repr(fsync_state))

        if os.name == 'nt' and not _windows_hint_shown:
            globals()['_windows_hint_shown'] = True
            warnings.append('Windows 上这几条路径未经验证：replace 被占用、长路径、只读目录；'
                            '真踩到问题请按 replace_failed 的提示处理。')
    except OutputError:
        raise
    except OSError as exc:
        raise OutputError(_output_kind(exc),
                          f'写不出去：{path}\n{exc.strerror or exc}\n'
                          '没有留下半成品。')
    finally:
        for leftover in (temp_path, backup):
            if os.path.exists(leftover):
                try:
                    os.unlink(leftover)
                except OSError:
                    pass
    return WriteResult(path, durable, warnings)


def read_json_input(path, what, next_step, expect=None):
    """读一份 JSON 输入。坏在哪、下一步做什么、属于哪一类，一次说清。
    每一样以前都会甩一段堆栈或者被当成正常数据吃掉。这里统一挡在门口。
    """
    try:
        with open(path, 'rb') as fh:
            raw = fh.read()
    except OSError:
        raise InputError('file_missing', f'{what}打不开：{path}\n{next_step}')
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise InputError('encoding_invalid',
                         f'{what}不是 UTF-8：{path}\n'
                         '可能是写的时候编码选错了，重跑一遍把它重新生成出来。\n' + next_step)
    if not text.strip():
        raise InputError('empty_input', f'{what}是空的：{path}\n{next_step}')

    deepest = json_depth(text)
    if deepest > MAX_JSON_DEPTH:
        raise InputError('depth_exceeded',
                         f'{what}嵌套 {deepest} 层，超过上限 {MAX_JSON_DEPTH}：{path}\n'
                         '这不是正常输出，八成是文件损坏或者被塞了别的东西。\n' + next_step)

    try:
        data = json.loads(text)
    except RecursionError:
        # 走到这儿说明层数没超上限但解释器还是崩了，兜底也带类别
        raise InputError('depth_exceeded',
                         f'{what}解不开，嵌套太深：{path}\n' + next_step)
    except json.JSONDecodeError as exc:
        kind = 'json_truncated' if exc.pos >= len(text.rstrip()) - 1 else 'json_malformed'
        raise InputError(kind,
                         f'{what}不是合法的 JSON：{path}\n'
                         f'  第 {exc.lineno} 行第 {exc.colno} 列：{exc.msg}\n'
                         + ('文件看起来被截断了。\n' if kind == 'json_truncated' else '')
                         + next_step)
    if expect is not None and not expect(data):
        raise InputError('shape_invalid',
                         f'{what}的形状不对：{path}\n'
                         '这不是那个脚本会输出的东西。\n' + next_step)
    return data


def load_probe(path):
    """读探针的输出。读不了就说清楚，别甩堆栈。"""
    next_step = ('先用 probe/run.js 跑一遍，把它的输出存成文件:\n'
                 '  node probe/run.js 应用目录 6 > probe.json')

    def shape(data):
        if not isinstance(data, dict):
            return False
        for key in ('handlers', 'listeners', 'windows'):
            value = data.get(key)
            if value is not None and not isinstance(value, list):
                return False
        return True

    return read_json_input(path, '运行时结果', next_step, expect=shape)


def load_poke(path):
    """敲击结果是一串记录，不是对象。读坏了还是那句话，但要说清坏在哪。"""
    next_step = ('先用 probe/poke.js 跑一遍:\n'
                 '  node probe/poke.js 应用目录 6 > poke.json')

    def shape(data):
        if not isinstance(data, list):
            return False
        return all(isinstance(row, dict) and 'channel' in row for row in data)

    return read_json_input(path, '敲击结果', next_step, expect=shape)


# 拦截类的话。抛错本身不算证据，得看它抛的是不是这一类。
GATE_WORDS = ('reject', 'denied', 'forbidden', 'unauthor', 'untrusted',
              'sender', 'not allowed', 'permission')


def classify_poke(rows):
    """把敲出来的结果分档。给人看的那节和 json 用的是同一份判断，不维护两份。"""
    if not isinstance(rows, list) or not rows:
        return {'channels': 0, 'swallowed': [], 'gated': [], 'unknown': [],
                'reasons': {}, 'error': rows.get('error') if isinstance(rows, dict) else None}

    by_channel = defaultdict(lambda: {'boom': [], 'ok': []})
    reasons = defaultdict(list)
    for row in rows:
        channel = row.get('channel', '?')
        if row.get('ok'):
            by_channel[channel]['ok'].append(row.get('payload', '?'))
        else:
            by_channel[channel]['boom'].append(row.get('payload', '?'))
            reasons[channel].append(str(row.get('error') or ''))

    swallowed = sorted(c for c, v in by_channel.items() if v['ok'])
    boom = [c for c, v in by_channel.items() if v['boom']]
    gated = sorted(c for c in boom
                   if reasons[c] and all(any(word in r.lower() for word in GATE_WORDS)
                                         for r in reasons[c]))
    unknown = sorted(c for c in boom if c not in gated)
    return {
        'channels': len(by_channel),
        'swallowed': swallowed,
        'swallowed_payloads': {c: by_channel[c]['ok'] for c in swallowed},
        'gated': gated,
        'unknown': unknown,
        'reasons': {c: reasons[c] for c in boom},
        'error': None,
    }


def render_poke(rows):
    """把「真敲了一遍」的结果摆出来。

    抛错不一定是坏事——可能人家本来就该拒。真正要看的是另一种：
    喂了空值、喂了十万个字符，它照收，还返回成功。
    """
    out = ['', '## 真的敲了一遍', '']
    if isinstance(rows, dict) and rows.get('error'):
        out.append(f'- 没跑起来：{rows["error"]}')
        out.append('')
        return out
    if not isinstance(rows, list) or not rows:
        out.append('- 没有结果')
        out.append('')
        return out

    buckets = classify_poke(rows)
    reasons = buckets['reasons']
    swallow, gated, business = buckets['swallowed'], buckets['gated'], buckets['unknown']

    out.append(f"- 敲了 {buckets['channels']} 条通道，每条四五种不合规的输入")
    out.append(f'- 照收 {len(swallow)} 条，被拦下 {len(gated)} 条，'
               f'别的错 {len(business)} 条')
    out.append('')

    if gated:
        out.append('### 被拦下的')
        out.append('')
        out.append('拦的话是程序自己说的，原话抄在下面。')
        out.append('这一档能证明的只有一件事：**有个门**，不合适的调用被挡在门外。')
        out.append('它证明不了门后面对参数做过校验——sender 校验管的是「谁在调」，')
        out.append('不是「传了什么」。所以这一档的正确读法是：有门，门后逻辑未审。')
        out.append('')
        shown = []
        for channel in gated[:12]:
            words = next((r for r in reasons[channel]
                          if any(w in r.lower() for w in GATE_WORDS)), '')
            out.append(f'- `{channel}`：{words.strip()[:90]}')
            shown.append(channel)
        if len(gated) > len(shown):
            out.append(f'- 还有 {len(gated) - len(shown)} 条同样被拦')
        out.append('')

    if business:
        out.append('### 这一档：门禁未知')
        out.append('')
        out.append('它抛了错，但抛的不是拦截类的话。所以这条错误**不提供门禁信息**——')
        out.append('既不能说它有门，也不能说它没有。')
        out.append('要判断得回去看代码，别把这一档读成「可以试试打穿」。')
        out.append('')
        for channel in business[:8]:
            words = reasons[channel][0] if reasons[channel] else ''
            out.append(f'- `{channel}`：{words.strip()[:90]}')
        if len(business) > 8:
            out.append(f'- 还有 {len(business) - 8} 条')
        out.append('')

    if swallow:
        out.append('### 照收的（该看一眼有没有校验）')
        out.append('')
        for channel in swallow[:15]:
            kinds = '、'.join(dict.fromkeys(buckets['swallowed_payloads'].get(channel, [])))
            out.append(f'- `{channel}`：喂 {kinds} 都照收，还返回了结果')
        if len(swallow) > 15:
            out.append(f'- 还有 {len(swallow) - 15} 条同样照收')
        out.append('')
        out.append('> 照收不等于有洞。但参数进来不看看就往下走，是这类通道最常见的问题。')
        out.append('')
    return out


def collect_evidence(result):
    graph = result['graph']
    summary = result.get('summary') or {}
    if 'summary' in summary and isinstance(summary['summary'], dict):
        summary = summary['summary']

    windows = []
    bridges = []
    for node in graph['nodes']:
        kind = node['kind']
        if kind not in ('browser-window', 'context-bridge-api'):
            continue
        for obs in node.get('observations', []):
            props = obs.get('properties') or {}
            where = loc(obs.get('evidence'))
            if kind == 'browser-window':
                prefs = {p['name']: p['value'] for p in props.get('web_preferences', [])}
                windows.append({'where': where, 'preload': props.get('preload_path'), 'prefs': prefs})
            else:
                bridges.append({'key': props.get('api_key') or props.get('key'),
                                'world': props.get('world'), 'where': where})

    invokes, handles, exports = defaultdict(set), defaultdict(set), defaultdict(set)
    for edge in graph['edges']:
        props = edge.get('properties') or {}
        channel = props.get('channel')
        relation = edge['relation']
        where = loc(edge.get('evidence'))
        if relation == 'invokes' and channel:
            invokes[channel].add(where)
        elif relation == 'handles' and channel:
            handles[channel].add(where)
        elif relation == 'calls' and channel:
            exports[props.get('entry') or '?'].add((channel, where))

    dyn_channels = []
    for edge in graph['edges']:
        if edge['relation'] not in ('invokes', 'handles'):
            continue
        props = edge.get('properties') or {}
        channel = props.get('channel')
        resolution = props.get('resolution')
        if channel and resolution in (None, 'literal'):
            continue
        expr = props.get('channel_expression') or channel or '?'
        dyn_channels.append((expr, loc(edge.get('evidence'))))

    families = []
    coverage = (result.get('semantic_graph') or {}).get('coverage') or {}
    for fam in coverage.get('families') or []:
        unknown = len(fam.get('unknown_ids') or [])
        if fam.get('status') != 'complete' or unknown:
            families.append({'name': fam.get('family'), 'status': fam.get('status'),
                             'unknown': unknown, 'retained': fam.get('retained_relations')})
    families.sort(key=lambda f: (-f['unknown'], f['name'] or ''))

    return {
        'mode': 'evidence',
        'subject': result.get('input_path') or '?',
        'sha': result.get('root_artifact_sha256') or '?',
        'stats': result.get('statistics') or {},
        'windows': windows,
        'bridges': bridges,
        'invokes': invokes,
        'handles': handles,
        'exports': exports,
        'channels': sorted(set(invokes) | set(handles)),
        'dyn_channels': sorted(set(dyn_channels)),
        'families': families,
        'ipc': summary.get('ipc') or {},
        'sender_checks': summary.get('sender_validation_observations'),
        'native_addons': summary.get('native_addon_bindings'),
    }


def audit_evidence(facts):
    findings = []
    for win in facts['windows']:
        values = {k: v.get('value') for k, v in win['prefs'].items() if v.get('status') == 'literal'}
        if values.get('nodeIntegration') is True:
            findings.append(('high', 'nodeIntegration 开着，页面能直接拿 Node', win['where']))
        if values.get('contextIsolation') is False:
            findings.append(('high', 'contextIsolation 关着，preload 和页面共用一个世界', win['where']))
        if 'sandbox' not in values:
            findings.append(('info', '没写 sandbox，走 Electron 默认值', win['where']))
    if facts['sender_checks'] == 0 and facts['windows']:
        findings.append(('high', '一条 sender 校验都没有，任何页面都能调这些通道', 'main 进程'))
    for channel in facts['channels']:
        low = channel.lower()
        if any(hint in low for hint in HIGH_RISK_HINTS):
            where = ', '.join(sorted(facts['invokes'].get(channel) or facts['handles'].get(channel)))
            findings.append(('medium', f'通道名带隐藏意味：{channel}', where))
        if channel in facts['handles'] and channel not in facts['invokes']:
            findings.append(('medium', f'主进程注册了，preload 没走这条：{channel}',
                             ', '.join(sorted(facts['handles'][channel]))))
    return findings


# 聚合字段登记表。每加一个「把多条信息压成一个数/一个布尔」的字段，
# 就得在这里登记它的明细字段和一个 must_not，否则 meta-test 会红。
# 这是第四次加聚合字段时会先漏再补的那个缺口，用检查堵上。
AGGREGATE_FIELDS = [
    {'field': 'strength', 'detail': 'strength_by_source',
     'must_not': 'use_strength_alone'},
    {'field': 'corroborated', 'detail': 'strength_by_source',
     'must_not': 'use_corroborated_as_uniform'},
    {'field': 'primary_action', 'detail': 'actions',
     'must_not': 'use_primary_action_alone'},
    {'field': 'weakest_strength', 'detail': 'weakest_sources',
     'must_not': 'use_weakest_without_list'},
]

# evidence 里每个名字允许出现的字段。不在这张白名单、也不在 AGGREGATE_FIELDS 里的新字段，
# 一律当成「疑似聚合字段」报出来——这是正向扫描，不是靠字段名字长得像。
EVIDENCE_FIELDS = {
    'sources', 'strength', 'where', 'actions', 'primary_action',
    'corroboration', 'corroborated', 'independent_pairs',
    'strength_by_source', 'weakest_sources', 'weakest_strength',
}


def unregistered_evidence_fields(entry):
    """正向检查：这条记录里有没有谁都没登记过的字段。

    聚合字段的判定规则就写在这儿——不是看名字像不像，是看它有没有登记。
    新加字段忘了登记，这里会报出来；判错的代价是必须去登记或加白名单，
    而不是等下次想起来。
    """
    registered = {agg['field'] for agg in AGGREGATE_FIELDS}
    return sorted(set(entry) - EVIDENCE_FIELDS - registered)


BASELINE_SCHEMA = 'ipcsurface/baseline/1'


def load_baseline(path):
    """读上次留下的那份基线。没有就当空的。

    基线是跨版本产物：旧基线配新报告，口径可能已经变了。
    所以基线自带 schema 号，对不上就拒绝，不静默按旧口径比——
    比出一个看着对其实错的结论，比没有结论更糟。
    """
    if not path:
        return {'findings': [], 'channels': [], 'schema': BASELINE_SCHEMA}
    data = read_json_input(
        path, '基线', '要么用当前版本重新写一份基线，要么人工比：\n'
        '  ipcsurface <包> --write-baseline <基线文件>',
        expect=lambda d: isinstance(d, dict))
    saved = data.get('schema')
    if saved != BASELINE_SCHEMA:
        raise SystemExit(
            '基线 schema 对不上：文件里是 {}，现在是 {}。\n'
            '旧基线可能按另一套口径算的，拿它比会得出看着对其实错的结论。\n'
            '下一步：用当前版本重新写一份基线，一条命令的事（真包也就几秒）。\n'
            '  ipcsurface <包> --write-baseline <基线文件>\n'
            '然后再用它比：ipcsurface <包> --baseline <基线文件>'.format(
                saved or '没有', BASELINE_SCHEMA))
    return {
        'findings': [tuple(item) for item in data.get('findings') or []],
        'channels': list(data.get('channels') or []),
    }


def save_baseline(path, findings, channels):
    payload = {
        'schema': BASELINE_SCHEMA,
        'findings': [list(item) for item in findings],
        'channels': list(channels),
    }
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print('基线写到 ' + path, file=sys.stderr)



def render_evidence(facts, findings, known_count=0, show_all=False):
    stats = facts['stats']
    out = ['# Electron 能力面清单', '']
    out.append(f"- 目标：`{facts['subject']}`")
    out.append(f"- 摘要 sha256：`{facts['sha'][:16]}…`")
    out.append(f'- {stamp()}')
    out.append(f"- 解析 {stats.get('parsed_javascript_files', '?')} 个 JS 文件，"
               f"{stats.get('visited_ast_nodes', '?')} 个 AST 节点，"
               f"失败 {stats.get('parse_failures', 0)} 个")
    out.append('')

    unknown_total = sum(f['unknown'] for f in facts['families'])
    blind = []
    if facts['dyn_channels']:
        blind.append(f"{len(facts['dyn_channels'])} 处通道名是算出来的")
    if unknown_total:
        blind.append(f"{unknown_total} 处关系没解析出来")
    out.append('## 这份报告能信多少')
    out.append('')
    if blind:
        out.append('有东西没看透：' + '、'.join(blind) + '。')
        out.append('表里没写的，不等于没有。')
    else:
        out.append('没撞上压过的代码，也没有算出来的通道名，表里写的差不多就是全部。')
    native = facts['native_addons'] or 0
    if native:
        out.append(f'- 挂了 {native} 个 native 模块，越界、泄漏、重复释放要找它们，不在 JS 这层')
    else:
        out.append('- 没挂 native 模块，越界这类本来就不该出在 JS 这层，硬查是空转')
    out.append('')

    out.append('## 窗口')
    if facts['windows']:
        for win in facts['windows']:
            prefs = ', '.join(f"{k}={v.get('value')}" for k, v in win['prefs'].items())
            out.append(f"- `{win['where']}` preload=`{win['preload']}` {prefs or '没写任何 webPreferences'}")
    else:
        out.append('- 没找到 BrowserWindow 构造')
    out.append('')

    out.append('## preload 暴露面')
    if facts['bridges']:
        for bridge in facts['bridges']:
            out.append(f"- 挂到 `window.{bridge['key']}`，world={bridge['world']}，`{bridge['where']}`")
    for entry in sorted(facts['exports']):
        for channel, where in sorted(facts['exports'][entry]):
            out.append(f"  - `{entry}` → `{channel}`  `{where}`")
    if not facts['bridges'] and not facts['exports']:
        out.append('- 没有 contextBridge 暴露')
    out.append('')

    out.append('## 通道表')
    out.append('')
    out.append('| 通道 | 页面侧 | 主进程侧 | 配对 |')
    out.append('| --- | --- | --- | --- |')
    limit = len(facts['channels']) if show_all else 30
    for channel in facts['channels'][:limit]:
        page = ', '.join(f'`{w}`' for w in sorted(facts['invokes'].get(channel) or ['—']))
        host = ', '.join(f'`{w}`' for w in sorted(facts['handles'].get(channel) or ['—']))
        paired = '是' if channel in facts['invokes'] and channel in facts['handles'] else '缺一半'
        out.append(f'| `{channel}` | {page} | {host} | {paired} |')
    if len(facts['channels']) > limit:
        out.append(f'| … 还有 {len(facts["channels"]) - limit} 条没列 | 加 `--all` 看全 | | |')
    if len(facts['channels']) > 12:
        groups = defaultdict(int)
        for channel in facts['channels']:
            groups[re.split(r'[:/.]', channel)[0] or channel] += 1
        out.append('')
        out.append('按前缀分组：' + '，'.join(f'`{k}` {v} 条' for k, v in
                                            sorted(groups.items(), key=lambda kv: -kv[1])[:8]))
    ipc = facts['ipc']
    paired_count = len([c for c in facts['channels'] if c in facts['invokes'] and c in facts['handles']])
    out.append('')
    out.append(f'字面通道 {len(facts["channels"])} 条，两头都对上 {paired_count} 条，'
               f'动态通道 {ipc.get("dynamic_channel_operations", 0)} 条')
    out.append('')

    out.append('## 没看清的地方')
    out.append('')
    out.append('这张表只能证明哪些看清了，不能证明没有什么。')
    out.append('')
    for expr, where in facts['dyn_channels'][:20]:
        out.append(f'- 通道名是算出来的不是写死的：`{expr}`  `{where}`')
    if not facts['dyn_channels'] and ipc.get('dynamic_channel_operations'):
        out.append(f"- {ipc['dynamic_channel_operations']} 个通道操作是动态的，名字没定下来")
    loud = [f for f in facts['families'] if f['unknown']]
    quiet = [f for f in facts['families'] if not f['unknown']]
    for fam in loud[:8]:
        out.append(f"- {fam['name']}：{fam['status']}，{fam['unknown']} 处没解析出来")
    if len(loud) > 8:
        out.append(f'- 另外 {len(loud) - 8} 类也有没解析出来的')
    if quiet:
        out.append(f"- 这 {len(quiet)} 类只覆盖了一部分：" + '、'.join(f['name'] for f in quiet))
    out.append('- 混淆过的代码认不出来；打包压缩后的通道名会被当成算出来的值')
    out.append('- 动态 require、eval、拼接出来的路径，进不了这张表')
    out.append('- 内存层面它不看，越界、泄漏、重复释放要在运行时或者 native 那边查')
    out.append('')

    out.append('## 可疑项')
    if known_count:
        out.append('')
        out.append(f'另有 {known_count} 条是基线里就有的，没列。这里只放这次新冒出来的。')
    if findings:
        order = {'high': 0, 'medium': 1, 'info': 2}
        for level, text, where in sorted(findings, key=lambda f: order.get(f[0], 9)):
            out.append(f'- [{level}] {text}  `{where}`')
    elif known_count:
        out.append('- 没有新的')
    else:
        out.append('- 没撞上规则')
    out.append('')
    out.append('> 依据静态语法，没有执行目标。「没写」不等于「没有」，也可能在别处设置。')
    out.append('')
    out.extend(next_steps(facts, findings))
    return '\n'.join(out)


def next_steps(facts, findings):
    """报告别停在免责声明上。给两三条具体的、能立刻动手的。"""
    lines = ['## 下一步', '']
    steps = []
    order = {'high': 0, 'medium': 1}
    for level, text, where in sorted(findings, key=lambda f: order.get(f[0], 9)):
        if level in order and len(steps) < 3:
            if '进程' in where:
                steps.append(f'{text} —— {where}')
            else:
                steps.append(f'先看 `{where}` —— {text}')
    for expr, where in facts['dyn_channels'][:2]:
        steps.append(f'去 `{where}` 看那一行，名字是算出来的，得人读')
    if not facts['windows']:
        steps.append('没找到 BrowserWindow，先确认是不是 Electron，或者入口藏在别的文件里')
    for channel in facts['channels'][:2]:
        if channel in facts['handles'] and channel not in facts['invokes']:
            steps.append(f'`{channel}` 只有主进程那头，去看看谁在调它')
    if not steps:
        steps.append('这份报告没撞上规则，可以往下看通道表自己过一遍')
    lines.extend(f'{i}. {s}' for i, s in enumerate(steps, 1))
    lines.append('')
    return lines


# ---------------------------------------------------------------- diff

def asar_as_diff_facts(facts):
    """把粗扫的结果摆成 diff 认得的样子。手上只有 asar 的时候也能比版本。"""
    handles, invokes = defaultdict(set), defaultdict(set)
    for name, where in facts['handlers']:
        handles[name].add(where)
    for name, where in facts['invokes']:
        invokes[name].add(where)
    return {
        'channels': sorted(set(handles) | set(invokes)),
        'handles': handles,
        'invokes': invokes,
        'dyn_channels': [(what, where) for what, where in facts['dynamic']],
        'families': [],
    }


def render_diff(old_facts, new_facts, old_name, new_name):
    old_set = set(old_facts['channels'])
    new_set = set(new_facts['channels'])
    added = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)
    out = ['# 两份能力面的差', '']
    out.append(f'- 旧：`{old_name}`')
    out.append(f'- 新：`{new_name}`')
    out.append('')
    out.append(f"通道：{len(old_set)} → {len(new_set)}")
    out.append('')
    out.append('## 新加的')
    if added:
        for channel in added:
            host = ', '.join(f'`{w}`' for w in sorted(new_facts['handles'].get(channel) or []))
            page = ', '.join(f'`{w}`' for w in sorted(new_facts['invokes'].get(channel) or []))
            out.append(f'- `{channel}`  主进程 {host or "—"}  页面 {page or "—"}')
    else:
        out.append('- 没有')
    out.append('')
    out.append('## 没了的')
    if removed:
        for channel in removed:
            out.append(f'- `{channel}`')
    else:
        out.append('- 没有')
    out.append('')
    out.append('## 没看清的变化')
    old_dyn = {(e, w) for e, w in old_facts['dyn_channels']}
    new_dyn = {(e, w) for e, w in new_facts['dyn_channels']}
    delta = sorted(new_dyn - old_dyn)
    if delta:
        for expr, where in delta[:20]:
            out.append(f'- 新增一处算出来的通道名：`{expr}`  `{where}`')
    else:
        out.append('- 没有')
    old_blind = sum(f['unknown'] for f in old_facts['families'])
    new_blind = sum(f['unknown'] for f in new_facts['families'])
    out.append('')
    out.append(f"未解析总数：{old_blind} → {new_blind}")
    out.append('')
    out.append('> 只比字面通道。算出来的那些不参与比对，出现在下面那一栏里。')
    return '\n'.join(out)


def render_runtime(probe, static_channels=None):
    """把探针跑出来的东西并进来。这一段是程序自己报的，不是猜的。"""
    out = ['', '## 跑起来之后看见的', '']
    if probe.get('error'):
        out.append(f'- 没跑起来：{probe["error"]}')
        out.append('')
        return out
    handlers = probe.get('handlers') or []
    out.append(f'- 主进程上挂着 {len(handlers)} 条 invoke 通道')
    missing = 0
    for name in handlers:
        mark = ''
        if static_channels is not None and name not in static_channels:
            mark = '  ← 静态那边没看见'
            missing += 1
        out.append(f'  - `{name}`{mark}')
    if missing:
        out.append(f'- 其中 {missing} 条静态没看见。可能是算出来的名字，也可能是 Electron 自己的，得看一眼')
    for win in probe.get('windows') or []:
        out.append(f"- 窗口：contextIsolation={win.get('contextIsolation')} "
                   f"nodeIntegration={win.get('nodeIntegration')} sandbox={win.get('sandbox')}")
        out.append(f"  preload={win.get('preload')}")
    out.append('')
    out.append('> 这些名字是程序自己报的。但注册过不等于调得到，还得看谁有权调。')
    return out


# ---------------------------------------------------------------- pe

# 一眼就知道不该乱来的那些。不是漏洞，是提醒。
DANGEROUS_IMPORTS = {
    'strcpy': '不查长度',
    'strcat': '不查长度',
    'wcscpy': '不查长度',
    'lstrcpyA': '不查长度',
    'lstrcpyW': '不查长度',
    'gets': '不查长度',
    'sprintf': '不查长度',
    'vsprintf': '不查长度',
    'wsprintfA': '不查长度',
    'memcpy': '长度可控时危险',
    'memmove': '长度可控时危险',
    'system': '起外部命令',
    'WinExec': '起外部命令',
    'ShellExecuteA': '起外部命令',
    'ShellExecuteW': '起外部命令',
    'CreateProcessA': '起外部命令',
    'CreateProcessW': '起外部命令',
    'LoadLibraryA': '运行时加载',
    'LoadLibraryW': '运行时加载',
    'GetProcAddress': '运行时找函数',
    'VirtualAlloc': '可执行内存',
    'WriteProcessMemory': '改别人的内存',
    'CreateRemoteThread': '往别人进程里塞线程',
}

PE_MAGIC = (b'MZ',)


def _rva_to_offset(rva, sections):
    for va, vsize, raw_ptr, raw_size in sections:
        if va <= rva < va + max(vsize, raw_size):
            return rva - va + raw_ptr
    return None


def read_pe_imports(path):
    """读 PE 的导入表。只回答一件事：这个模块引了外头哪些函数。"""
    with open(path, 'rb') as fh:
        data = fh.read()
    if data[:2] != b'MZ':
        raise SystemExit('这不是 PE：开头不是 MZ')
    try:
        pe_off = struct.unpack_from('<I', data, 0x3C)[0]
        if data[pe_off:pe_off + 4] != b'PE\0\0':
            raise SystemExit('这不是 PE：找不到 PE 签名')
        coff = pe_off + 4
        machine, nsections = struct.unpack_from('<HH', data, coff)
        size_opt = struct.unpack_from('<H', data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from('<H', data, opt)[0]
        is_64 = magic == 0x20B
        dirs = opt + (112 if is_64 else 96)
        import_rva, import_size = struct.unpack_from('<II', data, dirs + 8)
        sections = []
        sect = opt + size_opt
        for i in range(nsections):
            base = sect + i * 40
            vsize, va, raw_size, raw_ptr = struct.unpack_from('<IIII', data, base + 8)
            sections.append((va, vsize, raw_ptr, raw_size))
    except struct.error:
        raise SystemExit('这不是 PE：头部读不通')

    if not import_rva:
        return {'machine': machine, 'is_64': is_64, 'libraries': {}, 'sections': len(sections)}

    libraries = {}
    offset = _rva_to_offset(import_rva, sections)
    if offset is None:
        raise SystemExit('PE 导入表不在任何节里，可能被改过')
    thunk_size = 8 if is_64 else 4
    ordinal_flag = 1 << (63 if is_64 else 31)

    for _ in range(512):  # 防御：导入描述符不会太多
        desc = data[offset:offset + 20]
        if len(desc) < 20 or desc == b'\0' * 20:
            break
        original_thunk, _stamp, _chain, name_rva, first_thunk = struct.unpack('<IIIII', desc)
        name_off = _rva_to_offset(name_rva, sections)
        if name_off is None:
            break
        end = data.find(b'\0', name_off)
        dll = data[name_off:end].decode('latin-1', 'replace')
        funcs = []
        walk = original_thunk or first_thunk
        walk_off = _rva_to_offset(walk, sections) if walk else None
        if walk_off is not None:
            for _i in range(4096):
                raw = data[walk_off:walk_off + thunk_size]
                if len(raw) < thunk_size:
                    break
                value = int.from_bytes(raw, 'little')
                if value == 0:
                    break
                if value & ordinal_flag:
                    funcs.append(f'#{value & 0xFFFF}')
                else:
                    name_at = _rva_to_offset(value, sections)
                    if name_at is None:
                        funcs.append('?')
                    else:
                        # 跳过 2 字节 hint
                        fend = data.find(b'\0', name_at + 2)
                        funcs.append(data[name_at + 2:fend].decode('latin-1', 'replace'))
                walk_off += thunk_size
        libraries[dll] = funcs
        offset += 20

    return {'machine': machine, 'is_64': is_64, 'libraries': libraries, 'sections': len(sections)}


def audit_pe(facts):
    """导入表也能当门禁。同一条 --fail-on，三条路一个标准。"""
    names = {fn.split('@')[0] for funcs in facts['libraries'].values() for fn in funcs}
    findings = []
    if 'CreateRemoteThread' in names and 'WriteProcessMemory' in names:
        findings.append(('high', '既会改别人的内存，又会往别人进程里塞线程', '导入表'))
    for fn in sorted(names & set(DANGEROUS_IMPORTS)):
        if fn in ('CreateRemoteThread', 'WriteProcessMemory'):
            continue
        findings.append(('medium', f'{fn}：{DANGEROUS_IMPORTS[fn]}', '导入表'))
    return findings


def render_pe(target, facts, size):
    total = sum(len(v) for v in facts['libraries'].values())
    out = ['# 模块导入了什么', '']
    out.append(f'- 目标：`{os.path.abspath(target)}`')
    out.append(f'- {"64" if facts["is_64"] else "32"} 位，{facts["sections"]} 个节，'
               f'{size / 1024:.0f} KB')
    out.append(f'- {len(facts["libraries"])} 个动态库，{total} 个函数')
    out.append('')
    out.append('## 这份报告能信多少')
    out.append('')
    out.append('导入表只说「这个模块引了外头的哪些函数」，不说它怎么用。')
    out.append('同一个 strcpy，写对了就是写对了，写错才是洞。这里给的是线索，不是判决。')
    if '\\windows\\' in ('\\' + target.lower()) and ('system32' in target.lower()
                                                     or 'syswow64' in target.lower()):
        out.append('')
        out.append('这是系统自带的库。那几张表里的名字对它来说本来就该有，别拿这份报告去怀疑它。')
    out.append('')

    flagged = {}
    for dll, funcs in facts['libraries'].items():
        for fn in funcs:
            base = fn.split('@')[0]
            if base in DANGEROUS_IMPORTS:
                flagged.setdefault(base, []).append(dll)

    out.append('## 值得看一眼的')
    if flagged:
        out.append('')
        for fn in sorted(flagged):
            where = '、'.join(sorted(set(flagged[fn])))
            out.append(f'- `{fn}` — {DANGEROUS_IMPORTS[fn]}  （来自 {where}）')
    else:
        out.append('- 没撞上下面的表')
    out.append('')

    out.append('## 全部导入')
    out.append('')
    for dll in sorted(facts['libraries'], key=str.lower):
        funcs = facts['libraries'][dll]
        head = ', '.join(funcs[:12])
        more = f' …共 {len(funcs)} 个' if len(funcs) > 12 else ''
        out.append(f'- **{dll}**（{len(funcs)}）{head}{more}')
    out.append('')
    out.append('## 下一步')
    out.append('')
    if flagged:
        out.append(f'1. 去找 `{sorted(flagged)[0]}` 被调用的地方，看长度参数是从哪来的')
        out.append('2. 这批函数本身没错，错在传进去的值。反编译看调用点，不要看导入表')
    else:
        out.append('1. 导入表这边没什么可看的，换方向')
    out.append('2. 真要定漏洞，得上动态：喂异常输入看崩不崩')
    out.append('')
    out.append('> 只读文件头，不加载、不执行。')
    return '\n'.join(out)


# ---------------------------------------------------------------- cli

def looks_like_asar(path):
    return path.lower().endswith('.asar')


def looks_like_pe(path):
    return path.lower().endswith(('.exe', '.dll', '.node', '.pyd', '.efi', '.sys'))


def scan_sourcemaps(files):
    """包里带 sourcemap 的话，sourcesContent 里就是没压过的源码。

    真有这玩意儿，压缩包也能翻回原样——这是唯一能让「认出来 0 条」变成
    「认出来几条」的静态办法。
    """
    recovered = {}
    for rel, blob in files.items():
        if not rel.endswith('.map'):
            continue
        try:
            data = json.loads(blob.decode('utf-8', 'ignore'))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        contents = data.get('sourcesContent') or []
        sources = data.get('sources') or []
        for i, code in enumerate(contents):
            if not isinstance(code, str) or not code.strip():
                continue
            name = sources[i] if i < len(sources) else f'source{i}'
            recovered[f'{rel} → {name}'] = code.encode('utf-8')
    return recovered


# 长得像通道名的字符串：`前缀:名字`，两头都是字母数字。压缩过的代码里
# 调用点认不出，但这些字面量往往还留在原地。
CHANNELISH = re.compile(r'^[A-Za-z][A-Za-z0-9_-]{1,24}:[A-Za-z][A-Za-z0-9_.-]{1,48}$')
NOISE_PREFIX = {'http', 'https', 'file', 'data', 'mailto', 'chrome', 'ws', 'wss',
                'node', 'blob', 'about', 'javascript', 'utf', 'iso'}
STRING_LIT = re.compile(r"'([^'\\\n]{4,80})'" r'|"([^"\\\n]{4,80})"')
# 同一个模式，吃字节。整包转成字符串再找太贵，能不解码就不解码。
STRING_LIT_B = re.compile(STRING_LIT.pattern.encode('ascii'))
# 「长得像通道」的形状，直接写成一条字节正则：
# 前缀 2-25 个标识符字符，冒号，后缀 2-49 个。和 CHANNELISH 等价。
CHANNEL_LIT_B = re.compile(
    rb"""['"]([A-Za-z][A-Za-z0-9_-]{1,24}:[A-Za-z][A-Za-z0-9_.-]{1,48})['"]""")

JS_EXT = ('.js', '.mjs', '.cjs', '.jsx', '.ts')


DEP_MARKERS = ('/node_modules/', '/vendor/', '/third_party/', '/bower_components/')
TEST_MARKERS = ('.test.', '.spec.', '/test/', '/tests/', '/__tests__/', '/__mocks__/')


def classify_path(rel):
    """这个文件是谁写的。自己的 / 第三方 / 测试。

    不跳过它们——第三方里也可能藏着东西。只是分开摆，别混在一起吵。
    """
    low = '/' + rel.lower().replace('\\', '/').lstrip('/')
    if any(marker in low for marker in DEP_MARKERS):
        return 'dep'
    if any(marker in low for marker in TEST_MARKERS):
        return 'test'
    return 'self'


def harvest_strings(files):
    """压缩过的包里，调用点认不出了，但名字本身常常还躺在字符串里。

    这不是解析，是打捞。捞上来的不一定是通道，只保证「长得像」。
    顺手记下这个文件是谁的，好把第三方库那堆噪音分开放。

    找的时候直接在字节上找，只有真像通道的那几条才解码、才数行号。
    整包先转一遍字符串，是这一步以前最贵的地方。
    """
    seen = {}
    for rel, blob in files.items():
        if not rel.endswith(JS_EXT):
            continue
        kind = None
        # 直接把「长得像通道」的形状写进正则，让 C 那边筛，
        # 别把整包里几百万条字符串一条条搬进 Python 再判。
        for match in CHANNEL_LIT_B.finditer(blob):
            # 前面紧贴着标识符或者另一个引号，说明这段只是长字符串里的一截，
            # 比如 "x'font-style:italic'x" 里的那点 CSS，不是真的字面量边界。
            prev = blob[match.start(1) - 2:match.start(1) - 1]
            if prev.isalnum() or prev in (b"'", b'"', b'`'):
                continue
            value = match.group(1).decode('ascii')
            prefix = value.split(':', 1)[0]
            if prefix.lower() in NOISE_PREFIX:
                continue
            # A1:A13 这种是 Excel 单元格，不是通道
            if re.fullmatch(r'[A-Za-z]{1,3}\d{1,5}', prefix):
                continue
            if value in seen:
                continue
            if kind is None:
                kind = classify_path(rel)
            line = blob.count(b'\n', 0, match.start()) + 1
            seen[value] = (f'{rel}:{line}', kind)
    return seen


def analyse_asar(path, allow_eval=True, max_passes=1):
    header, files = read_asar(path)
    # 文件表是开着源文件按需切的，用完得自己关。Windows 上不关，
    # 这个包删都删不掉。
    try:
        facts = scan_asar(files, allow_eval=allow_eval, max_passes=max_passes)
        recovered = scan_sourcemaps(files)
        if recovered:
            extra = scan_asar(recovered)
            for key in ('exposes', 'handlers', 'invokes', 'dynamic', 'preloads', 'obfuscation'):
                merged = set(facts[key]) | set(extra[key])
                facts[key] = sorted(merged)
            facts['scanned'] += extra['scanned']
        facts['recovered'] = sorted(recovered)
        facts['harvested'] = harvest_strings(files)
        total = files.total_bytes()
        return facts, len(files), total
    finally:
        files.close()


EXIT_CODES = {
    0: '没有触发门禁',
    1: '输入有问题（文件不存在、不是 asar、参数不对）',
    2: '--fail-on 被触发',
    3: '内部错误：工具自己崩了，不是目标的问题',
    4: '报告已写入但未持久化（目录 fsync 失败，崩溃后可能回退）；'
       '文件已是新版，不要回滚、不要重跑',
}


def render_sarif(target, findings, version):
    """SARIF 2.1.0。CI 平台直接能读，不用为每个平台写一遍解析。

    只把「可疑项」放进去。通道清单、可信度分层那些不是告警，
    塞进 SARIF 会被当成告警计数，反而失真。
    """
    level_map = {'high': 'error', 'medium': 'warning', 'info': 'note'}
    rules, results = {}, []
    for level, text, where in findings:
        # 规则 id 要是 ASCII：中文标题转成 slug 会空，空了就用文字摘要兜底，
        # 同一条规则每次都得到同一个 id，CI 才能拿它做抑制和分类。
        slug = re.sub(r'[^A-Za-z0-9]+', '-', text.split('：')[0])[:40].strip('-')
        if not slug:
            slug = 'finding-' + hashlib.sha1(text.encode('utf-8')).hexdigest()[:10]
        rule_id = 'ipcsurface/' + slug.lower()
        rules.setdefault(rule_id, {
            'id': rule_id,
            'name': slug[:40],
            'shortDescription': {'text': text},
            'defaultConfiguration': {'level': level_map.get(level, 'note')},
        })
        path, _, line = where.rpartition(':')
        location = {'physicalLocation': {'artifactLocation': {'uri': path or where}}}
        if line.isdigit():
            location['physicalLocation']['region'] = {'startLine': int(line)}
        results.append({
            'ruleId': rule_id,
            'level': level_map.get(level, 'note'),
            'message': {'text': f'{text}（{where}）'},
            'locations': [location],
        })
    return {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {'driver': {
                'name': 'ipcsurface',
                'version': version,
                'informationUri': 'https://github.com/irrational51444/ipcsurface',
                'rules': list(rules.values()),
            }},
            'automationDetails': {'id': 'ipcsurface/' + version},
            'results': results,
        }],
    }


def main(argv=None):
    # Windows 控制台默认不是 UTF-8，直接打中文会乱码
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding='utf-8')
        except (AttributeError, ValueError):
            pass

    epilog = '''退出码
  0  成功；持久性看 stderr 的 kind 行（durability_unknown = 本平台无法确认）
  1  输入有问题（文件不存在、不是 asar、参数不对）
  2  --fail-on 被触发
  3  工具自己崩了，不是目标的问题
  4  已写入但未持久化（目录 fsync 失败）；文件已是新版，不要回滚、不要重跑

写失败时 stderr 带一行 kind: <类别>，输入侧与输出侧的类别见 README。'''

    parser = argparse.ArgumentParser(
        prog='ipcsurface',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='把一个 Electron 应用的能力面压成一页纸。'
                    '输入可以是 .asar、REA 的 Evidence JSON，或者一个 dll/exe。',
        epilog=epilog + '\n\n报告第一节永远是「这份报告能信多少」，然后是证据，最后是下一步。')
    parser.add_argument('input', help='.asar 包、REA 的 Evidence JSON，或 dll/exe')
    parser.add_argument('--version', action='version', version=f'ipcsurface {__version__}')
    parser.add_argument('-o', '--out', help='写到文件，不给就打到标准输出')
    parser.add_argument('--format', choices=('md', 'json', 'sarif'), default='md',
                        help='md 给人看，json 给程序读，sarif 直接喂 CI 平台')
    parser.add_argument('--fail-on', choices=('high', 'medium'), help='出现该级别问题时以退出码 2 结束')
    parser.add_argument('--diff', metavar='OTHER', help='把 input 当成旧版，和另一份 Evidence 比')
    parser.add_argument('--all', action='store_true', help='不截断，把找到的全列出来')
    parser.add_argument('--baseline', metavar='FILE',
                        help='上次的发现，这次只报新冒出来的')
    parser.add_argument('--write-baseline', metavar='FILE',
                        help='把这次的发现存成基线，下次用 --baseline 读它')
    parser.add_argument('--runtime', metavar='PROBE_JSON',
                        help='probe/run.js 的输出，把跑起来看见的通道并进报告')
    parser.add_argument('--no-eval', action='store_true',
                        help='关掉自解码还原。默认开着：它只做模式匹配，不执行目标里的代码')
    parser.add_argument('--deep-restore', action='store_true',
                        help='还原多转几趟。默认一趟：实测多转在这批样本上没多认出东西，还慢')
    parser.add_argument('--poke', metavar='POKE_JSON',
                        help='probe/poke.js 的输出，把真敲一遍的结果并进报告')
    args = parser.parse_args(argv)

    if not os.path.exists(args.input):
        raise SystemExit(f'没这个文件：{args.input}')
    if os.path.isdir(args.input):
        raise SystemExit(f'这是个目录，不是文件：{args.input}\n'
                         '要分析没打包的应用，用 probe/run.js，不要用这个命令')

    if args.diff and args.baseline:
        print('注意：比版本的时候 --baseline 用不上，这次忽略它', file=sys.stderr)

    if args.diff:
        # 两边可以都是 asar，也可以都是 Evidence——手上只有包的时候也能比
        def side(path):
            if looks_like_asar(path):
                facts, _count, _total = analyse_asar(path)
                return asar_as_diff_facts(facts)
            return collect_evidence(load_record(path))

        old = side(args.input)
        new = side(args.diff)
        if args.format == 'json':
            old_set, new_set = set(old['channels']), set(new['channels'])
            text = json.dumps({
                'mode': 'diff',
                'old': args.input,
                'new': args.diff,
                'added': sorted(new_set - old_set),
                'removed': sorted(old_set - new_set),
                'channels': {'old': len(old_set), 'new': len(new_set)},
                'version': __version__,
            }, ensure_ascii=False, indent=2)
        else:
            text = render_diff(old, new, os.path.basename(args.input), os.path.basename(args.diff))
        findings = []
        old_set, new_set = set(old['channels']), set(new['channels'])
        summary_line = f'新增 {len(new_set - old_set)} 条，消失 {len(old_set - new_set)} 条'
    elif looks_like_asar(args.input):
        facts, count, total = analyse_asar(args.input, allow_eval=not args.no_eval,
                                           max_passes=6 if args.deep_restore else 1)
        findings = audit_asar(facts)
        names = {n for n, _ in facts['handlers']} | {n for n, _ in facts['invokes']}
        probe_data = load_probe(args.runtime) if args.runtime else None
        poke_data = load_poke(args.poke) if args.poke else None
        if args.format == 'json':
            checks = runtime_crosscheck(probe_data, names)
            evidence = channel_sources(facts, probe=probe_data)
            poke_buckets = classify_poke(poke_data) if poke_data else None
            text = json.dumps(
                build_asar_report(args.input, facts, count, total, names, evidence,
                                  checks, poke_buckets, load_baseline(args.baseline)
                                  if args.baseline else None),
                ensure_ascii=False, indent=2)
        else:
            text = render_asar(args.input, facts, count, total,
                               show_all=args.all, findings=findings,
                               probe=probe_data, poke=poke_data,
                               baseline=load_baseline(args.baseline) if args.baseline else None)
        if args.write_baseline:
            save_baseline(args.write_baseline, findings, facts['channels'])
        names = {n for n, _ in facts['handlers']} | {n for n, _ in facts['invokes']}
        summary_line = f'{len(names)} 条通道，{len(facts["dynamic"])} 处名字是算的'
        # JSON 和 SARIF 都是结构化的，再往里拼 markdown 会把它弄成不是那个格式。
        if args.format == 'sarif':
            text = json.dumps(render_sarif(args.input, findings, __version__),
                              ensure_ascii=False, indent=2)
        elif args.format != 'json':
            if probe_data:
                text += '\n'.join(render_runtime(probe_data, names))
            if poke_data:
                text += '\n'.join(render_poke(poke_data))
    elif looks_like_pe(args.input):
        facts = read_pe_imports(args.input)
        findings = audit_pe(facts)
        size = os.path.getsize(args.input)
        if args.format == 'json':
            flagged = sorted({fn.split('@')[0] for funcs in facts['libraries'].values()
                              for fn in funcs if fn.split('@')[0] in DANGEROUS_IMPORTS})
            text = json.dumps({
                'mode': 'pe',
                'subject': args.input,
                'bits': 64 if facts['is_64'] else 32,
                'libraries': {k: v for k, v in facts['libraries'].items()},
                'flagged': flagged,
                'version': __version__,
            }, ensure_ascii=False, indent=2)
        else:
            text = render_pe(args.input, facts, size)
        total_funcs = sum(len(v) for v in facts['libraries'].values())
        summary_line = f"{len(facts['libraries'])} 个库，{total_funcs} 个函数"
    else:
        facts = collect_evidence(load_record(args.input))
        findings = audit_evidence(facts)
        if args.write_baseline:
            save_baseline(args.write_baseline, findings, facts['channels'])
        known_count = 0
        if args.baseline:
            known = {(text, where) for _level, text, where in load_baseline(args.baseline)['findings']}
            fresh = [f for f in findings if (f[1], f[2]) not in known]
            known_count = len(findings) - len(fresh)
            findings = fresh
        hot = len([f for f in findings if f[0] in ('high', 'medium')])
        summary_line = (f"{len(facts['channels'])} 条通道，{hot} 条可疑，"
                        f"{len(facts['dyn_channels'])} 处名字是算的")
        if known_count:
            summary_line += f'，压掉旧的 {known_count} 条'
        if args.format == 'json':
            payload = {
                'subject': facts['subject'],
                'channels': facts['channels'],
                'paired': [c for c in facts['channels']
                           if c in facts['invokes'] and c in facts['handles']],
                'dynamic': [expr for expr, _ in facts['dyn_channels']],
                'bridges': facts['bridges'],
                'windows': facts['windows'],
                'findings': [{'level': l, 'text': t, 'location': w} for l, t, w in findings],
            }
            text = json.dumps(payload, ensure_ascii=False, indent=2)
        else:
            text = render_evidence(facts, findings, known_count=known_count, show_all=args.all)
            if args.runtime:
                probe = load_probe(args.runtime)
                text += '\n'.join(render_runtime(probe, set(facts['channels'])))
            if args.poke:
                text += '\n'.join(render_poke(load_poke(args.poke)))

    if args.out:
        parent = os.path.dirname(os.path.abspath(args.out))
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        result = write_output(args.out, text,
                             expect_json=args.format in ('json', 'sarif'))
        undurable = result.durable == DURABLE_NO
        unknown = result.durable == DURABLE_UNKNOWN
        for note in result.warnings:
            print('注意：' + note, file=sys.stderr)
        if undurable:
            # 文件已经是新版，只是持久化没保证；这不是失败，但必须让 CI 看得见
            print('kind: not_durable', file=sys.stderr)
        elif unknown and not _unknown_note_shown:
            globals()['_unknown_note_shown'] = True
            print('kind: durability_unknown', file=sys.stderr)
        # 一行就说完，人不用打开文件也知道要不要看
        print(f'wrote {args.out} — {summary_line}', file=sys.stderr)
    else:
        print(text)

    if undurable:
        return 2 if (args.fail_on and findings) else 4
    if args.fail_on and findings:
        order = {'high': 0, 'medium': 1, 'info': 2}
        if any(order.get(level, 9) <= order[args.fail_on] for level, _, _ in findings):
            return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
