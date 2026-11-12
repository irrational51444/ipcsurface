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



# ---------------------------------------------------------------- asar

from jsasar import AsarFiles, read_asar
def stamp():
    "报告里带生成时间和版本；版本号只有主模块知道，所以在这儿补上。"
    return jsreport.stamp(__version__)


__version__ = '0.100.0'

# 报告 schema 的唯一出处。build_asar_report 和指纹都用它，别再散着写。
SCHEMA_VERSION = 'ipcsurface/asar/23'

from jslabels import (DANGER_KIND_MAP, HARVEST_GRADES,  # noqa: E402
                      danger_kind_of)
import jsreport  # noqa: E402
from jsreport import (  # noqa: E402
    ACTION_BY_SOURCE, ACTION_STRICTNESS, ALL_SOURCES, ENUM_STRENGTH_OPEN, ENUM_STRENGTH_PROVEN,
    HIGH_RISK_HINTS, INDEPENDENCE_TABLE, REFUTES, SINK_TIER_ORDER, SOURCE_STRENGTH, STATIC_SOURCES,
    _build_independence, audit_asar, baseline_delta, channel_profiles, channel_sources,
    confidence_ladder, confidence_levels, corroboration_strength, fingerprint_of, independent,
    input_sha256, refutes_if, render_asar, render_baseline, sample_sites, sink_tier,
)

jsreport.VERSION = __version__   # 报告层的版本号由这儿注入
jsreport.SCHEMA = SCHEMA_VERSION  # schema 也一样，别让指纹里写死旧值
import jslabels  # noqa: E402
import native_imports  # noqa: E402  # noqa: E402  asar 解析层单独成文件，这里重新导出

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

# IPC 之外的能力面。路线图 P1-5：顶尖的能力面清单不该只有 ipcMain/ipcRenderer。
# 每一项是一个独立的「面」，带证据强度进报告；主线只进计数+样本，全量进 JSON。
# 这里只负责「认出来」，强弱判断（guard 有没有）在 describe 那层做。
ATTACK_PATTERNS = [
    ('shell-open', re.compile(r"shell\.(?:openExternal|openPath|showItemInFolder)\(\s*")),
    ('exec-js', re.compile(r"\.executeJavaScript\(\s*")),
    ('permission-handler', re.compile(r"\.setPermission(?:Request|Check)Handler\(\s*")),
    ('custom-protocol', re.compile(r"protocol\.(?:handle|registerFileProtocol|registerBufferProtocol|"
                                  r"registerStreamProtocol|registerHttpProtocol|registerSchemesAsPrivileged)\(\s*")),
    ('deep-link', re.compile(r"setAsDefaultProtocolClient\(\s*|app\.on\(\s*['\"]open-url|"
                             r"app\.on\(\s*['\"]second-instance")),
    ('webview', re.compile(r"<webview\b|webviewTag\s*:\s*true|WebContentsView")),
]
ATTACK_LABELS = {
    'shell-open': 'shell 打开外部链接/文件',
    'exec-js': 'executeJavaScript 注入',
    'permission-handler': '权限请求处理器',
    'custom-protocol': '自定义协议',
    'deep-link': '深链 / 第二实例',
    'webview': 'webview / WebContentsView',
}


def _classify_arg(text, pos):
    """看一个调用点第一个参数是死值还是活值。

    pos 是左括号之后的位置。死值（字符串/数字）说明写死了，活值（变量/表达式/
    函数调用）才可能来自外部——只标这一档，不替它下「一定危险」的结论。
    """
    i = pos
    while i < len(text) and text[i] in ' \t\n':
        i += 1
    if i >= len(text):
        return 'empty'
    ch = text[i]
    if ch in ('"', "'", '`'):
        return 'literal'
    if ch.isdigit() or ch in '-+':
        return 'literal'
    return 'variable'


def line_of(text, pos):
    return text.count('\n', 0, pos) + 1




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
    # 先花常数时间看一眼：没有「引号 + 加号 + 引号」就没有可折的。
    # 这条守卫把整包还原从 13 秒压到几秒——正则跑在四百兆上是真贵。
    if "' +" not in text and '" +' not in text and "+'" not in text and '+"' not in text:
        return text
    for _ in range(4):
        folded = CONCAT_QUOTES.sub(
            lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), text)
        if folded == text:
            break
        text = folded
    return text


# ------------------------------------------------------- 穷举「拼出来的名字」
# 拼出来的名字有两种。一种写在别处，代回去就行（上面那套常量传播）；
# 另一种是「一小组取值 × 一个拼装函数」：
#
#     const OPS = ['add', 'list', 'remove'];
#     for (const op of OPS) ipcMain.handle(makeChannel(op), …)
#     function makeChannel(rest) { return 'ledger:' + rest; }
#
# 这种不是猜：取值集合有限、写在源码里，拼法也只有字面量和加号，穷举出来就是全部。
# 超出这个范围的（读配置、循环里累加、查完表再拼）仍旧算不出来——那是真边界，
# 不往上凑一个「大概是这样」。

ENUM_MAX_VALUES = 64        # 一个变量最多枚举这么多个取值
ENUM_MAX_NAMES = 256        # 一个调用点最多展开这么多名字
ENUM_MAX_DEPTH = 3          # 函数套函数最多跟三层
ENUM_SCAN_LIMIT = 40000     # 找循环体大括号时最多往后看这么多字符

# 穷举要提强度，得先补证明。三条都能在源码里查，查不了就不许挂高强度的名字。
# 它们各自对应一句「什么情况会让这次穷举算错」——
# 不是修辞，是这三条真的能推翻结果：
#   1) 循环里改过循环变量 → 取值集合不是那三个；
#   2) 数组在别处被 push/splice/改元素 → 集合不是字面量那三个；
#   3) 拼装函数不是「一个字面量表达式」→ 拼法不成立。
ENUM_CHECKS = ('loop_var_not_reassigned', 'array_not_mutated', 'helper_is_single_expression')

ARRAY_MUTATORS = ('.push(', '.pop(', '.shift(', '.unshift(', '.splice(',
                  '.sort(', '.reverse(', '.fill(', '.copyWithin(', '.sort (')

ARRAY_LITERAL_DEF = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\[\s*"
    r"((?:['\"](?:\\.|[^'\"\\])*['\"]\s*,?\s*){1,%d})\s*\]" % ENUM_MAX_VALUES)
STRING_ITEM = re.compile(r"""(['"])((?:\\.|(?!\1)[^\\])*)\1""")
SIMPLE_FUNC_DEF = re.compile(
    r"function\s+([A-Za-z_$][\w$]*)\s*\(([^)]{0,200})\)\s*\{\s*return\s+([^;{}]{1,300});?\s*\}")
SIMPLE_ARROW_DEF = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\(([^)]{0,200})\)\s*=>\s*([^;{}\n]{1,300})")
FOR_OF_HEAD = re.compile(r"for\s*\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s+of\s+([^)]{1,600})\)")
FOR_EACH_HEAD = re.compile(
    r"forEach\s*\(\s*(?:function\s*\(([A-Za-z_$][\w$]*)[^)]*\)|\(?([A-Za-z_$][\w$]*)\)?\s*=>)\s*\{")
IPC_HEADS = re.compile(
    r"ipcMain(?:\.(?:handle|handleOnce|on)|\[\s*['\"](?:handle|handleOnce|on)['\"]\s*\])"
    r"|ipcRenderer(?:\.(?:invoke|send|sendSync)|\[\s*['\"](?:invoke|send|sendSync)['\"]\s*\])")


def _skip_string(text, pos):
    """pos 指在引号上，返回这个字面量之后的位置。模板串只按反引号算，不解析 ${}。"""
    quote = text[pos]
    i = pos + 1
    limit = min(len(text), pos + 4096)
    while i < limit:
        char = text[i]
        if char == '\\':
            i += 2
            continue
        if char == quote:
            return i + 1
        i += 1
    return limit


def _split_top(text, sep=','):
    """按顶层分隔符切分，跳过引号和括号。切不开返回 None。"""
    parts, depth, start, i = [], 0, 0, 0
    while i < len(text):
        char = text[i]
        if char in '\'"`':
            i = _skip_string(text, i)
            continue
        if char in '([{':
            depth += 1
        elif char in ')]}':
            depth -= 1
            if depth < 0:
                return None
        elif char == sep and depth == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    if depth != 0:
        return None
    parts.append(text[start:])
    return [part.strip() for part in parts]


def _block_end(text, open_pos):
    """从 `{` 开始找到配对的 `}`，跳过字符串。找不到返回 None。"""
    depth, i, limit = 0, open_pos, min(len(text), open_pos + ENUM_SCAN_LIMIT)
    while i < limit:
        char = text[i]
        if char in '\'"`':
            i = _skip_string(text, i)
            continue
        if char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


SPLIT_DEF = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
    r"""(['"])((?:\\.|(?!\2)[^\\]){0,400})\2\s*\.\s*split\s*\(\s*"""
    r"""(['"])(.)\4\s*\)""")
OBJ_KEYS_DEF = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*Object\s*\.\s*"
    r"(keys|values)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)")
SPREAD_DEF = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\[\s*([^\[\]]{0,600})\s*\]")
CONCAT_DEF = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*\.\s*"
    r"concat\s*\(\s*\[([^\[\]]{0,600})\]\s*\)")


def parse_array_literals(text):
    """收「取值集合完全由源码字面量决定」的数组常量。

    不只是 `const OPS = ['a','b']` 这一种。真项目里更常见的是这几种，
    它们同样能算出全部取值，所以一起收：

    - `'a,b,c'.split(',')`（分隔符必须是单字符字面量）
    - `Object.keys({a: 1, b: 2})` / `Object.values({...})`（对象字面量的字段）
    - `[...A, ...B]` / `[...A, 'c']`（展开，元素都是已知集合）
    - `A.concat(['c'])`

    迭代到不再增长为止：B 依赖 A、C 依赖 B 这种链子也能展开。
    """
    table = {}
    for match in ARRAY_LITERAL_DEF.finditer(text):
        values = tuple(value for _quote, value in STRING_ITEM.findall(match.group(2)))
        if values:
            table.setdefault(match.group(1), values)

    objects = parse_object_literals(text)
    splits = {}
    for match in SPLIT_DEF.finditer(text):
        source, sep = match.group(3), match.group(5)
        if sep and source:
            splits.setdefault(match.group(1), (source, sep))
    spreads = {}
    for match in SPREAD_DEF.finditer(text):
        spreads.setdefault(match.group(1), match.group(2))
    concats = {}
    for match in CONCAT_DEF.finditer(text):
        concats.setdefault(match.group(1), (match.group(2), match.group(3)))
    keydefs = {}
    for match in OBJ_KEYS_DEF.finditer(text):
        keydefs.setdefault(match.group(1), (match.group(2), match.group(3)))

    def expand_items(body):
        """把 `[...A, 'x']` 这种元素串展开；有一个元素算不出就整条放弃。"""
        parts = _split_top(body)
        if parts is None:
            return None
        values = []
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if part.startswith('...'):
                name = part[3:].strip()
                if name not in table:
                    return None
                values.extend(table[name])
                continue
            match = STRING_ITEM.fullmatch(part)
            if not match:
                return None
            values.append(match.group(2))
        return tuple(values) if values else None

    for _round in range(4):
        grew = False
        for name, (source, sep) in splits.items():
            if name in table:
                continue
            pieces = tuple(piece for piece in source.split(sep) if piece)
            if pieces and len(pieces) <= ENUM_MAX_VALUES:
                table[name] = pieces
                grew = True
        for name, (kind, target) in keydefs.items():
            if name in table or target not in objects:
                continue
            fields = objects[target]
            values = tuple(fields) if kind == 'keys' else tuple(fields.values())
            if values:
                table[name] = values
                grew = True
        for name, body in spreads.items():
            if name in table:
                continue
            values = expand_items(body)
            if values:
                table[name] = values
                grew = True
        for name, (source, body) in concats.items():
            if name in table or source not in table:
                continue
            extra = expand_items(body)
            if extra:
                table[name] = tuple(table[source]) + extra
                grew = True
        if not grew:
            break
    return table


def parse_simple_functions(text):
    """单表达式函数：`function f(a) { return 'x' + a; }` 和箭头版。

    只收「函数体就是一个表达式」的。带分支、带赋值、带循环的一律不收——
    那种拼法不是穷举能算的，硬算就是编。
    """
    table = {}
    for match in SIMPLE_FUNC_DEF.finditer(text):
        params = [p.strip() for p in match.group(2).split(',') if p.strip()]
        table[match.group(1)] = (params, match.group(3).strip())
    for match in SIMPLE_ARROW_DEF.finditer(text):
        params = [p.strip() for p in match.group(2).split(',') if p.strip()]
        table.setdefault(match.group(1), (params, match.group(3).strip()))
    return table


def parse_loops(text, arrays):
    """找出遍历「有限取值」的循环：[(开始, 结束, 变量名, 取值元组, 来源说明)]。"""
    loops = []
    for match in FOR_OF_HEAD.finditer(text):
        source = match.group(2).strip()
        values = arrays.get(source)
        if values is None and source.startswith('['):
            values = tuple(value for _quote, value in STRING_ITEM.findall(source))
        if not values:
            continue
        brace = text.find('{', match.end())
        if brace != -1 and not text[match.end():brace].strip():
            end = _block_end(text, brace)
            if end is None:
                continue
            loops.append((brace, end, match.group(1), values, source))
    for match in FOR_EACH_HEAD.finditer(text):
        var = match.group(1) or match.group(2)
        brace = match.end() - 1
        end = _block_end(text, brace)
        if end is None:
            continue
        # forEach 的数组在调用点左边：OPS.forEach(…) ——往前取一个标识符
        before = text[max(0, match.start() - 120):match.start()]
        names = re.findall(r'([A-Za-z_$][\w$]*)\s*\.\s*$', before)
        if not names:
            continue
        values = arrays.get(names[0])
        if not values:
            continue
        loops.append((brace, end, var, values, names[0]))
    return loops


def _eval_atom(atom, env, funcs, depth, used=None):
    """一个「加号之间」的片段能取哪些值。算不出返回 None。

    used 记下这个表达式用到了哪些拼装函数——那些函数能不能撑住穷举，
    要单独查（见 _helper_is_clean）。
    """
    text = atom.strip()
    if not text:
        return None
    while len(text) > 1 and text[0] == '(' and text[-1] == ')':
        text = text[1:-1].strip()
    if text[:1] in ('"', "'") and len(text) >= 2:
        match = STRING_ITEM.match(text)
        return frozenset([match.group(2)]) if match else None
    if text[:1] == '`':
        return _eval_template(text, env, funcs, depth, used)
    call = re.match(r'^([A-Za-z_$][\w$]*)\s*\((.*)\)$', text, re.S)
    if call:
        if depth >= ENUM_MAX_DEPTH:
            return None
        entry = funcs.get(call.group(1))
        if not entry:
            return None
        if used is not None and call.group(1) not in used:
            used.append(call.group(1))
        params, body = entry
        args = _split_top(call.group(2)) if call.group(2).strip() else []
        if args is None or len(args) != len(params):
            return None
        inner = dict(env)
        for name, arg in zip(params, args):
            value = _eval_value(arg, env, funcs, depth + 1, used)
            if value is None:
                return None
            inner[name] = value
        return _eval_value(body, inner, funcs, depth + 1, used)
    if re.match(r'^[A-Za-z_$][\w$]*$', text):
        return env.get(text)
    return None


def _eval_template(text, env, funcs, depth, used=None):
    """模板串：`ledger:${op}`。只支持 ${标识符} 和 ${'字面量'}。"""
    body = text[1:-1] if text.endswith('`') else text[1:]
    total = ['']
    i = 0
    while i < len(body):
        if body.startswith('${', i):
            end = body.find('}', i)
            if end == -1:
                return None
            value = _eval_atom(body[i + 2:end], env, funcs, depth, used)
            if value is None:
                return None
            total = [a + b for a in total for b in sorted(value)]
            if len(total) > ENUM_MAX_NAMES:
                return None
            i = end + 1
            continue
        total = [a + body[i] for a in total]
        i += 1
    return frozenset(total)


def _eval_value(expr, env, funcs, depth=0, used=None):
    """把一个表达式算成「可能的取值集合」。算不出返回 None。"""
    parts = _split_top(expr, '+')
    if not parts:
        return None
    total = ['']
    for part in parts:
        values = _eval_atom(part, env, funcs, depth, used)
        if values is None:
            return None
        total = [a + b for a in total for b in sorted(values)]
        if len(total) > ENUM_MAX_NAMES:
            return None
    return frozenset(total)


def _first_argument(text, open_paren):
    """取调用括号里的第一个实参原文。取不到返回 None。"""
    depth, i, limit = 0, open_paren + 1, min(len(text), open_paren + 2000)
    start = i
    while i < limit:
        char = text[i]
        if char in '\'"`':
            i = _skip_string(text, i)
            continue
        if char in '([{':
            depth += 1
        elif char == ')':
            if depth == 0:
                return text[start:i].strip()
            depth -= 1
        elif char == ',' and depth == 0:
            return text[start:i].strip()
        i += 1
    return None


def array_def_spans(text):
    """每种「取值集合由字面量决定」的数组定义各自的位置，用来把定义处排除掉。

    排除是为了查「别处有没有改过它」：定义那一行本身就写着 `NAME = …`，
    不排除的话每次都会误判成「被重新赋值」。
    """
    spans = {}
    for pattern in (ARRAY_LITERAL_DEF, SPLIT_DEF, OBJ_KEYS_DEF, SPREAD_DEF, CONCAT_DEF):
        for match in pattern.finditer(text):
            spans.setdefault(match.group(1), (match.start(), match.end()))
    return spans


def _mask_span(text, start, end):
    """把一段替换成等长空格：行号不变，别处再扫就扫不到它。"""
    return text[:start] + ' ' * (end - start) + text[end:]


def _loop_var_is_clean(body, var):
    """循环体里有没有改过循环变量。改过就说明取值集合不是那三个。

    认这几种：`op = …`、`op += …`、`op++`、`[a, op] = …`、`({op} = …)`。
    这里是「查不出问题才给高强度」，所以宁可漏认也不误认——
    误认会让一条本来对的穷举降档，漏认会让一条错的穷举升档，后者更坏。
    """
    name = re.escape(var)
    if re.search(r'(?<![\w$.])' + name + r'\s*(?:\+=|-=|\*=|/=|\+\+|--|=(?!=))', body):
        return False
    if re.search(r'(?:\[|\{)[^\]\}\)]{0,80}(?<![\w$.])' + name +
                 r'(?![\w$])[^\]\}\)]{0,80}(?:\]|\})\s*=(?!=)', body):
        return False
    return True


def _array_is_clean(text, name, def_span):
    """数组常量除了那一处定义，别处有没有被动过。

    动过的意思：`OPS.push(…)` 这类原地改、`OPS[0] = …` 改元素、`OPS = …` 重绑。
    被整个摊开（`[...OPS]`）不算动——取值还在。
    """
    if def_span is None:
        return False
    masked = _mask_span(text, def_span[0], def_span[1])
    name_re = re.escape(name)
    for mutator in ARRAY_MUTATORS:
        if re.search(r'(?<![\w$.])' + name_re + re.escape(mutator.rstrip()), masked):
            return False
    if re.search(r'(?<![\w$.])' + name_re + r'\s*\[[^\]]{0,60}\]\s*=(?!=)', masked):
        return False
    if re.search(r'(?<![\w$.])' + name_re + r'\s*=(?!=)', masked):
        return False
    return True


def _helper_is_clean(params, body):
    """拼装函数是不是「单一字面量表达式」。带展开参数就算不成立。"""
    if any('...' in param for param in params):
        return False
    return bool(body) and '=>' not in body


def enumerate_computed_names(text, rel):
    """把「有限取值 × 字面量拼装」的调用点穷举成具体名字。

    返回 [(kind, name, where, basis, 通过的检查, 没通过的检查)]。
    算不出来的一律不返回——那种留给 dynamic 那一档照实报「名字是算的」。
    检查没全过的仍然返回，但强度低一档，并把没过的检查写在证据里。
    """
    if 'for' not in text and 'forEach' not in text:
        return []
    arrays = parse_array_literals(text)
    loops = parse_loops(text, arrays)
    if not loops:
        return []
    funcs = parse_simple_functions(text)
    array_defs = array_def_spans(text)
    consts = {name: frozenset([value])
              for name, _quote, value in CONST_DEF.findall(text)}

    found = []
    for head in IPC_HEADS.finditer(text):
        paren = text.find('(', head.end())
        if paren == -1:
            continue
        if text[head.end():paren].strip():
            continue
        expr = _first_argument(text, paren)
        if not expr:
            continue
        # 只有落在某个循环体里，才谈得上穷举
        loop = next((item for item in loops if item[0] <= paren <= item[1]), None)
        if loop is None:
            continue
        env = dict(consts)
        env[loop[2]] = frozenset(loop[3])
        used = []
        values = _eval_value(expr, env, funcs, used=used)
        if not values:
            continue

        # 三条证明，各自对应一句「什么情况会让这次穷举算错」
        passed, failed = [], []
        body = text[loop[0]:loop[1] + 1]
        if _loop_var_is_clean(body, loop[2]):
            passed.append('loop_var_not_reassigned')
        else:
            failed.append('loop_var_not_reassigned')
        source = loop[4]
        if source.startswith('[') or _array_is_clean(text, source, array_defs.get(source)):
            passed.append('array_not_mutated')
        else:
            failed.append('array_not_mutated')
        dirty = [name for name in used if not _helper_is_clean(*funcs[name])]
        if dirty:
            failed.append('helper_is_single_expression')
        elif used:
            passed.append('helper_is_single_expression')

        kind = 'handle' if text.startswith('ipcMain', head.start()) else 'invoke'
        where = f'{rel}:{line_of(text, head.start())}'
        basis = f'{loop[2]} 在 {loop[4]} 里取 {len(loop[3])} 个值，拼法 {expr}'
        for name in sorted(values):
            found.append((kind, name, where, basis, tuple(passed), tuple(failed)))
    return found


# 一条通道「能碰到什么」——这是能力面，不是风险评级。
# 只扫处理函数体内看得见的 API 名和校验字样：
#   看见 child_process 只说明这里能执行命令，不说明它会被滥用；
#   看见 senderFrame 只说明有人写了校验，不说明校验有效（门禁存在 ≠ 门后安全）。
CAPABILITY_PATTERNS = [
    ('命令执行', re.compile(r'\b(?:child_process|execSync|execFile|execFileSync|spawn|spawnSync)\b')),
    ('文件写', re.compile(r'\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream'
                        r'|unlink|unlinkSync|rmSync|rename|renameSync|mkdir|mkdirSync)\b')),
    ('文件读', re.compile(r'\b(?:readFile|readFileSync|readdir|readdirSync|createReadStream'
                        r'|readJson|readFileSync)\b')),
    ('网络', re.compile(r'\b(?:fetch|http\.request|https\.request|net\.connect|axios)\b')),
    ('动态求值', re.compile(r'\b(?:eval|new Function|vm\.runIn)\b')),
    ('剪贴板', re.compile(r'\b(?:clipboard\.(?:readText|writeText|readImage))\b')),
]
GUARD_PATTERNS = [
    ('来源校验字样', re.compile(r'\b(?:senderFrame|validateSender|checkSender|isTrusted'
                          r'|sender\.getURL|event\.sender\b)')),
    ('参数校验字样', re.compile(r'\b(?:typeof\s+\w+|instanceof|Object\.keys\(\w+\)\.length'
                          r'|Array\.isArray|Number\.isInteger)\b')),
]
CAPABILITY_LEVELS = ('high-capability-no-guard-seen', 'high-capability-guard-seen',
                     'no-capability-seen', 'unknown')
HIGH_CAPABILITIES = ('命令执行', '文件写', '文件读', '动态求值')


def bound_call_args(text, start):
    """从调用括号往后，取到配对的右括号。取不到返回 None。"""
    depth, i, limit = 0, start, min(len(text), start + 8000)
    while i < limit:
        char = text[i]
        if char in '\'"`':
            i = _skip_string(text, i)
            continue
        if char in '([{':
            depth += 1
        elif char in ')]}':
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
        i += 1
    return None


def describe_capability(body):
    """一条处理函数体能碰到什么、有没有看见校验字样。

    返回 (能力列表, 校验列表, 等级)。等级名里带 `seen`——它说的是「看见了什么」，
    不是「这通道风险高」。看不见处理函数体（压缩成一处、或被拆走）就是 unknown。
    """
    if body is None:
        return [], [], 'unknown'
    caps = [name for name, pattern in CAPABILITY_PATTERNS if pattern.search(body)]
    guards = [name for name, pattern in GUARD_PATTERNS if pattern.search(body)]
    if not caps:
        return [], guards, 'no-capability-seen'
    high = [name for name in caps if name in HIGH_CAPABILITIES]
    if not high:
        return caps, guards, 'no-capability-seen'
    return caps, guards, ('high-capability-guard-seen' if guards
                          else 'high-capability-no-guard-seen')


LOCAL_FUNC_DEF = re.compile(
    r"(?:function\s+([A-Za-z_$][\w$]*)\s*\([^)]{0,200}\)\s*\{"
    r"|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]{0,200}\)\s*=>\s*\{)")


def local_function_bodies(text):
    """同一个文件里，每个函数名对应的函数体。只跟一层用。"""
    # 常数时间预筛：没有 function 也没有箭头函数，就不必跑那条正则。
    # 压缩包里绝大多数文件都过不了这道筛，省下来的是整份文本的扫描。
    if 'function' not in text and '=>' not in text:
        return {}
    bodies = {}
    for match in LOCAL_FUNC_DEF.finditer(text):
        name = match.group(1) or match.group(2)
        open_brace = text.find('{', match.end() - 1)
        if open_brace == -1:
            continue
        end = _block_end(text, open_brace)
        if end is None:
            continue
        bodies.setdefault(name, text[open_brace + 1:end])
    return bodies


def follow_one_hop(body, text, funcs=None):
    """跟一层：处理函数里调到的本文件函数，把它们的身也扫一遍。

    真项目里通道处理函数常常只是转发壳（`services.pick()` / `doThing(payload)`），
    能力全在被调的那一层。只跟一层，是因为再往下就分不清是这次调用还是别处调用；
    跟一层能把「什么都没看见」降下来一些，但跟不动服务层里的业务分支。
    返回 (合并后的文本, 跟到的函数名列表)。
    """
    if body is None:
        return None, []
    # 先看这段身里到底调没调东西：一个调用都没有，就不必为它建整份文件的函数表。
    # 真包里大量处理函数是 (...args)=>win.webContents.send(...) 这种，直接就没得跟。
    calls = re.findall(r'(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(', body)
    if not calls:
        return body, []
    if isinstance(funcs, dict):
        table = funcs.get('table')
        if table is None:
            table = funcs['table'] = local_function_bodies(text)
    else:
        table = funcs if funcs is not None else local_function_bodies(text)
    funcs = table
    seen, pieces = [], []
    for name in calls:
        inner = funcs.get(name)
        if inner and name not in seen:
            seen.append(name)
            pieces.append(inner)
        if len(seen) >= 12:
            break
    return body + '\n' + '\n'.join(pieces), seen


def _offset_of(text, line, column):
    """把「第几行第几列」换成字符偏移。行和列都从 0 起算（REA 的约定）。"""
    offset = 0
    for _ in range(line):
        nxt = text.find('\n', offset)
        if nxt == -1:
            return len(text)
        offset = nxt + 1
    return min(len(text), offset + column)


def capability_from_evidence(result):
    """有 Evidence 时：用它给的行列回原文切出处理函数体，再判能力。

    REA 的 `ipc-handler` 节点带 `handler_location`（source + start/end 行列），
    比自己拿括号配对硬切准得多。它不给函数体、也不连边，所以切完还是用同一套
    API 字样去判——变的只是「切得准」，不是「猜得更狠」。
    """
    path = (result or {}).get('input_path')
    graph = (result or {}).get('graph') or {}
    if not path or not os.path.exists(path) or not graph.get('nodes'):
        return {}
    try:
        header, files = read_asar(path)
    except (OSError, ValueError):
        return {}
    texts, out = {}, {}
    try:
        for node in graph['nodes']:
            if node.get('kind') != 'ipc-handler':
                continue
            for obs in node.get('observations') or []:
                props = obs.get('properties') or {}
                name = props.get('channel')
                where = ((obs.get('evidence') or {}).get('location') or {}).get('value') or {}
                if not name or where.get('kind') != 'source-range':
                    continue
                source = where.get('source')
                if source not in texts:
                    blob = files.get(source) if source in files else None
                    texts[source] = blob.decode('utf-8', 'ignore') if blob else ''
                text = texts[source]
                start = _offset_of(text, where['start']['line'], where['start']['column'])
                end = _offset_of(text, where['end']['line'], where['end']['column'])
                body = text[start:end] if end > start else None
                caps, guards, level = describe_capability(body)
                out[name] = {'apis': caps, 'guards': guards, 'level': level,
                             'where': f"{source}:{where['start']['line'] + 1}",
                             'from': 'ast'}
    except (KeyError, TypeError):
        return out
    finally:
        files.close()
    return out


def runtime_diff(static_names, probe):
    """静态名单和运行时观测的差集。

    三堆东西，各有各的意思：
      static_only —— 源码里写着，程序跑起来没注册（死代码、条件分支没走到、被拆走）
      runtime_only—— 跑起来注册了，静态没看见（拼出来的名字、动态注册）
      both        —— 两边都对上，这才是能当结论的
    不合并、不覆盖，三堆都留着——合并就把「哪边缺了什么」这条信息抹掉了。
    """
    static = set(static_names or ())
    runtime = set((probe or {}).get('handlers') or ()) | set((probe or {}).get('listeners') or ())
    if (probe or {}).get('error'):
        return {'static_only': sorted(static), 'runtime_only': [],
                'both': [], 'note': '探针没跑通，差集算不出来'}
    return {
        'static_only': sorted(static - runtime),
        'runtime_only': sorted(runtime - static),
        'both': sorted(static & runtime),
    }


CROSS_VERDICTS = {
    'confirmed': '静态看见能力、运行时也注册了',
    'dead-or-conditional': '静态写着，运行时没注册——死代码、条件没走到，或者被拆走了',
    'hidden-capability': '运行时注册了，静态没看见能力——能力藏在别处或名字是拼的',
    'untested': '没有运行时观测，判不了',
}


def cross_capability_runtime(capability, static_names, probe):
    """把能力面和运行时差集交叉起来，给每条通道一句判词。

    这不是评级：'confirmed' 只说明这条通道在源码里能碰某个 API、并且程序确实
    注册了它；能不能被滥用仍然要人看。
    """
    diff = runtime_diff(static_names, probe)
    if diff.get('note'):
        return {name: 'untested' for name in static_names or ()}
    runtime = set((probe or {}).get('handlers') or ()) | set((probe or {}).get('listeners') or ())
    out = {}
    for name in set(static_names or ()) | runtime:
        info = (capability or {}).get(name) or {}
        has_cap = bool(info.get('apis'))
        if not probe or probe.get('error'):
            out[name] = 'untested'
        elif name in runtime and has_cap:
            out[name] = 'confirmed'
        elif name in runtime:
            out[name] = 'hidden-capability'
        elif has_cap:
            out[name] = 'dead-or-conditional'
        else:
            out[name] = 'untested'
    return out
POKE_STATES = {
    'gated': '敲了一下，被拦下——只证明有门，门后逻辑没审',
    'swallowed': '敲了一下，照收还回了结果——值得看一眼有没有校验',
    'other-error': '抛了别的错，不提供门禁信息',
    'untested': '没敲过',
}


def attach_poke(verdicts, gated=(), swallowed=(), other=()):
    """把「敲没敲过」并到每条通道的判词旁边。

    分开存两个字段，不压成一个结论：能力面说的是「它能碰什么」，
    poke 说的是「被敲的时候它怎么反应」。两件事都对，但不能互相替代。
    """
    gated, swallowed, other = set(gated), set(swallowed), set(other)
    out = {}
    for name, verdict in (verdicts or {}).items():
        if name in gated:
            state = 'gated'
        elif name in swallowed:
            state = 'swallowed'
        elif name in other:
            state = 'other-error'
        else:
            state = 'untested'
        out[name] = {'verdict': verdict, 'poke': state}
    return out


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


def scan_asar(files, allow_eval=True, max_passes=1, events=None):
    """按字符串扫一遍源码。粗，但不用装任何东西。

    events 传一个 jsevents.EventBus 就能把过程录成事件流；传 None 时零开销
    （每个 emit 点第一行就是 `if events is None`）。
    """
    exposes, handlers, invokes = [], [], []
    dynamic, prefs, preloads = [], {}, []
    obfuscation = []
    resolved = set()   # 靠还原才认出名字的那些，强度低一档
    capability = {}    # 通道名 → 处理函数体能碰到什么（能力面，不是风险评级）
    attack_surface = {}   # IPC 之外的能力面：facets → [{where, snippet}]
    enumerated = []    # 穷举出来的名字，(名字, 位置, 依据)
    enumerated_sites = set()
    scanned = 0
    total_files = len(files)
    started_at = time.monotonic()
    # 先收一遍全包的常量，跨文件那种才配得上
    global_consts, global_members = build_global_tables(files)

    for index, (rel, blob) in enumerate(files.items(), start=1):
        # 实时进度：每 100 个文件报一次，或者最后一个文件必报。
        # 采样是为了不拖慢扫描——设计文档要求实时开销 < 5%。
        if events is not None and (index % 100 == 0 or index == total_files):
            events.emit('progress', {
                'files_done': index,
                'files_total': total_files,
                'elapsed_ms': int((time.monotonic() - started_at) * 1000),
            }, phase='coarse')
        if not rel.endswith(TEXT_EXT):
            continue
        # 先用字节找标记。解成字符串再找，慢十倍不止。
        # ipcRenderer 也要算热：只有页面侧调用的文件（没 contextBridge、没 ipcMain）
        # 以前整份被跳过，那条 invoke 就白丢了。
        # IPC 之外的能力面也在这层认（shell.openExternal 之类），它们不是 ipc 但同样危险。
        hot_ipc = (b'ipcMain' in blob or b'ipcRenderer' in blob
                   or b'contextBridge' in blob or b'webPreferences' in blob
                   or b'shell.' in blob or b'executeJavaScript' in blob
                   or b'setPermission' in blob or b'protocol.' in blob
                   or b'ProtocolClient' in blob or b'WebContentsView' in blob
                   or b'<webview' in blob)
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
        # 本文件的函数体只建一次：一个文件里常有几十条通道，
        # 以前每条都重扫一遍整份文本找函数定义，是这轮最贵的一笔。
        local_funcs = {}   # 一份缓存：真要跟的时候才建函数表
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
                    if kind == 'handle':
                        body = bound_call_args(text, match.start())
                        followed, _via = follow_one_hop(body, text, local_funcs)
                        caps, guards, level = describe_capability(followed)
                        if caps or level != 'unknown':
                            capability[value] = {'apis': caps, 'guards': guards,
                                                   'level': level, 'where': where}
                elif kind in ('dynamic_handle', 'dynamic_invoke'):
                    if not value.startswith(("'", '"')):
                        dynamic.append((f'{kind.split("_")[1]}: {value}', where))
                elif kind == 'preload':
                    preloads.append((value, where))
                else:
                    prefs[kind] = (value, where)

        # IPC 之外的能力面：一个文件扫一遍，按面归堆。这里只认「出现」，
        # 但对 shell-open / exec-js 额外判一档「参数是死字面量还是活的」——
        # 死的是写死的值，活的才可能来自外部，这一档决定证据强弱。
        for facet, pattern in ATTACK_PATTERNS:
            for match in pattern.finditer(text):
                where = f'{rel}:{line_of(text, match.start())}'
                snippet = text[match.start():match.start() + 40].strip()
                hit = {'where': where, 'snippet': snippet}
                if facet in ('shell-open', 'exec-js'):
                    hit['arg'] = _classify_arg(text, match.end())
                attack_surface.setdefault(facet, []).append(hit)

        # 算出来的名字：能穷举就穷举成具体名字，穷举不了的留在 dynamic 里照实报。
        # 用还原之后的文本：常量代回去之后，拼装式子才看得清。
        # 先在字节上看一眼有没有循环——绝大多数文件没有，没必要为它跑四条正则。
        # 只认 `for(` / `for (` / `forEach`：光找 `for` 会撞上 information 这类词。
        has_loop = (b'for(' in blob or b'for (' in blob or b'forEach' in blob)
        if has_loop:
            for kind, name, where, basis, passed, failed in enumerate_computed_names(text, rel):
                (handlers if kind == 'handle' else invokes).append((name, where))
                enumerated.append((name, where, basis, passed, failed))
                enumerated_sites.add(where)

    # 已经穷举出来的调用点不再算「名字是算的」——那处现在有名字了。
    dynamic = [item for item in dynamic if item[1] not in enumerated_sites]

    facts = {
        'scanned': scanned,
        'exposes': sorted(set(exposes)),
        'handlers': sorted(set(handlers)),
        'invokes': sorted(set(invokes)),
        'dynamic': sorted(set(dynamic)),
        'capability': capability,
        'enumerated': sorted(set(enumerated)),
        'preloads': sorted(set(preloads)),
        'prefs': prefs,
        'attack_surface': attack_surface,
        'obfuscation': sorted(set(obfuscation))[:200],
        'native_files': sorted(rel for rel in files if rel.endswith(('.node', '.dll'))),
        'native_imports': native_imports.native_import_surface(files),
        'nested_asar': sorted(rel for rel in files if rel.endswith('.asar')),
        'resolved': sorted(resolved),
        # 通道就是主进程注册和页面侧调用的那些名字，不含 window 上暴露的 API。
        # 口径要和报告里「N 条通道」一致，否则基线存一份、报告说另一份。
        'channels': sorted({name for name, _w in handlers} | {name for name, _w in invokes}),
    }

    # 实时层：把这一遍扫出来的东西逐条发出去。
    # discovery 用最终 channels（口径和报告一致），stats 带分层计数。
    if events is not None:
        for name in facts['channels']:
            events.emit('discovery', {
                'entity': 'channel', 'name': name, 'tier': None,
            }, phase='coarse')
        events.emit('stats', {
            'channels': len(facts['channels']),
            'sinks': 0,   # sink 要等 channel_sinks_map 跑完，在 analyse_asar 里补
            'unresolved': len(facts['dynamic']),
            'files_done': total_files,
            'files_total': total_files,
            'elapsed_ms': int((time.monotonic() - started_at) * 1000),
        }, phase='coarse')

    return facts




# 独立性判定表：不是举几个例子，是把全部两两组合写死。没点名的地方最容易按自己的理解走。








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
    {'id': 'universal_assertions_declare_empty_policy',
     'text': '测试里出现全称断言（assertTrue(all( 等）时，同一函数内必须有 non_empty(...) '
             '或 # empty-allowed 注释；由一条 AST 扫描用例每次执行，不靠人工扫'},
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
    {'id': 'recover_reports_without_restoring',
     'text': '崩溃残留只报告不自动还原：副本存在只能说明「可能崩在替换与清理之间」，'
             '判断不了 target 是新版还是旧版，猜错会把新报告换回旧的'},
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
    {'id': 'enumerated_requires_literal_set',
     'text': '穷举只在「取值集合是字面量数组、拼法只有字面量和加号」时发生；'
             '取值来自配置、函数返回值或循环累加的一律退回 dynamic，不猜；'
             '展开数量超过上限也整处退回，不截断了交点半份'},
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
                '静态来源之间（literal / literal-resolved / enumerated / computed / harvested）'
                '共享同一份源码，不算独立；运行时与任一静态来源算独立。'
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
            'id': 'corroboration_level_is_not_uniform',
            'text': '两路对上也分档：同文件相邻行和两个不同文件不是一回事。'
                    '引用档位时必须带 corroboration_basis，说明凭什么叫这一档。',
            'must_not': ['use_corroboration_level_alone'],
            'instead': '看 corroboration_basis；没有位置就是 unknown，别补一个「强」',
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



# 穷举那条分两档，按三条检查的结果定，不是统一调上去：
# 三条全过 → 0.9（和「靠还原」同档：证据链完整，逐条能复核）；
# 有一条没过 → 0.6（名字照给，但别当准的用）。




def all_sites(facts):
    """全量证据位置表：名字 → 所有见过的位置（去重、保序）。

    md 里只抽两条给人看；下游想做批量交叉验证，得有一份不抽样的。
    """
    out = {}
    for name, where in (facts['handlers'] + facts['invokes'] + facts['exposes']):
        out.setdefault(name, [])
        if where and where not in out[name]:
            out[name].append(where)
    for what, where in facts['dynamic']:
        out.setdefault(what, [])
        if where and where not in out[what]:
            out[what].append(where)
    for name, value in (facts.get('harvested') or {}).items():
        where = value[0] if isinstance(value, tuple) and value else None
        out.setdefault(name, [])
        if where and where not in out[name]:
            out[name].append(where)
    return out












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
    # 探针可以带位置（name -> "file:line"）。带了我们才敢给交叉定档；
    # 格式不对的不认，直接丢掉——宁可 unknown，也不拿垃圾位置算强度。
    sites = {}
    for name, where in (probe.get('sites') or {}).items():
        if isinstance(where, str) and ':' in where:
            sites[name] = where
    return {
        'handlers': handlers,
        'listeners': probe.get('listeners') or [],
        'windows': probe.get('windows') or [],
        'sites': sites,
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


def main_process_obfuscated(facts):
    """主进程文件是不是强混淆。是这个包最要紧的一句话：静态扫描对它基本失效。

    真踩过：bilibili 的 main/index.js 是 obfuscator.io 最高档混淆，连 ipcMain 都被
    换成 `_0x...`，字符串全编码——最后只认出 1 条（还是第三方库的）。报告如果只说
    「1 条通道」，读的人会以为这包真只有 1 条；必须顶在前面说「主进程看不到」。
    """
    strong = {w.split(':', 1)[0] for _n, w, level in (facts.get('obfuscation') or [])
              if level == 'strong'}
    hits = [p for p in strong
            if p in ('index.js', 'main/main.js', 'main/index.js')
            or (p.startswith('main/') and p.endswith('.js'))]
    return sorted(hits)


def blind_spots(facts, probe=None, poke=None):
    """这份报告看不到的地方。和 md 那节「没看清的地方」是同一份清单。"""
    items = ['混淆过、压过、名字算出来的代码，我一条都认不出来；所以「没看见」永远是未知，不是没有']
    main_obf = main_process_obfuscated(facts)
    if main_obf and not probe:
        # 这条必须排在最前面：它说明「这个包的通道数基本不可信」，不是小提醒
        items.insert(0, f"主进程文件是强混淆（{'、'.join(main_obf)}）：静态扫描对它基本失效，"
                        f"这包认出的通道数是「看不到」的结果，不是「没有」——要准的得跑运行时探针")
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








# 完整性凭证能证明什么、不能证明什么——写成字段，不再只是文档里的一句话。
# 以前「Merkle 根不是安全评级」只活在 README 和代码注释里，谁都能顺手把它
# 读成「这包干净」。现在它跟着凭证一起出现在报告里，读的人绕不过去。
INTEGRITY_CLAIM = {
    'proves': ['identity', 'unchanged_since_digest'],
    'does_not_prove': ['safety', 'absence_of_backdoor', 'behaviour_reviewed'],
    'security_rating': False,
    'read_as': '能对上只说明是同一份东西、生成后没被改过；不说明这包安全',
}


def archive_merkle(files):
    """包内文件的 Merkle 根：路径 + 每个文件内容的 sha256，按路径排序后聚合。

    作用只有一个：别人拿到同一个包，能算出同一个根，确认「我们说的是同一份东西」。
    """
    entries = []
    for name in sorted(files):
        digest = hashlib.sha256(files[name]).hexdigest()
        entries.append(f'{name}:{digest}')
    blob = '\n'.join(entries).encode('utf-8')
    return {'files': len(entries), 'root': hashlib.sha256(blob).hexdigest(),
            'algorithm': 'sha256(sorted(path:sha256) joined by newline)',
            'claim': dict(INTEGRITY_CLAIM)}


def content_digest(report):
    """报告正文自己的指纹：去掉时间戳与自身 digest 后算。

    任何人拿到这份报告都能重算一遍——对得上，说明这份报告没被改过、
    也不是别的版本生成的。
    """
    body = {k: v for k, v in report.items()
            if k not in ('generated_at', 'content_digest')}
    fp = dict(report.get('fingerprint') or {})
    fp.pop('digest', None)
    body['fingerprint'] = fp
    blob = json.dumps(body, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')
    return {'algorithm': 'sha256(canonical-json, 去掉 generated_at 与 fingerprint.digest)',
            'digest': hashlib.sha256(blob).hexdigest(),
            'claim': dict(INTEGRITY_CLAIM)}








def pick_main_js(files):
    """挑「这个应用自己的主进程入口」，别挑 node_modules 里的。

    真包踩过一次：抖音和 bilibili 的包里 npm 依赖也带 ipcMain，
    按「最大 + 含 ipcMain」挑会挑到 node_modules/@annie/... 去，
    于是这两家报 0 条通道——那不是它们干净，是我看错了文件。
    顺序：package.json 的 main 字段 → 不在 node_modules 的、带 ipcMain 的、
    路径最浅的、最大的。
    """
    names = [rel for rel in files.keys() if rel.endswith('.js')]

    manifest = None
    for rel in files.keys():
        if rel.endswith('package.json') and rel.count('/') <= 1:
            blob = files[rel]
            if not blob:
                continue
            try:
                manifest = json.loads(blob.decode('utf-8', 'ignore'))
                base = rel[:-len('package.json')]
            except ValueError:
                continue
            break
    if manifest and isinstance(manifest.get('main'), str):
        target = base + manifest['main'].lstrip('./')
        for candidate in (target, target + '.js', target + '/index.js'):
            if candidate in files:
                return candidate

    def score(rel):
        depth = rel.count('/')
        inside_deps = 'node_modules/' in rel
        has_ipc = bool(files[rel]) and b'ipcMain' in files[rel]
        return (inside_deps, depth, 0 if has_ipc else 1, -len(files[rel] or b''))

    candidates = [rel for rel in names if files[rel]]
    if not candidates:
        return None
    return sorted(candidates, key=score)[0]




# 限定长度的写法会在没引号的超长行上疯狂回溯：2.2 万个文件的样本跑了两分半。
# 改成把值整段吃掉、事后判长度，回溯就没了。
CONST_PAIR_RE = re.compile(r'([A-Za-z_$][\w$]*)\s*:\s*"([^"\\]*)"')
CONST_CACHE = {}




def iter_string_pairs(text):
    """扫出 `名字: "值"` 这种配对。手写循环，不用正则。

    正则版本在 2.2 万个文件的样本上跑了 80 秒——全是回溯的账。
    这里只做一次线性扫描：找到冒号、跳过空白、看是不是引号、往前取标识符。
    """
    pos = 0
    length = len(text)
    while True:
        pos = text.find(':', pos)
        if pos < 0 or pos + 1 >= length:
            return
        j = pos + 1
        while j < length and text[j] in ' \t':
            j += 1
        if j >= length or text[j] != '"':
            pos += 1
            continue
        end = j + 1
        while end < length:
            ch = text[end]
            if ch == '\\':
                end += 2
                continue
            if ch == '"':
                break
            if ch == '\n':
                end = length
                break
            end += 1
        if end >= length:
            return
        k = pos - 1
        while k >= 0 and text[k] in ' \t':
            k -= 1
        stop = k
        while k >= 0 and (text[k].isalnum() or text[k] in '_$'):
            k -= 1
        name = text[k + 1:stop + 1]
        if name:
            yield name, text[j + 1:end]
        pos = end + 1


def package_const_strings(files):
    """整包里「键 → 字符串值集合」的表，用来给三层成员链兜名字。

    只在唯一时用得上（调用方自己判），所以这里不挑，先攒齐。
    """
    cached = CONST_CACHE.get(id(files))
    if cached is not None:
        return cached
    table = {}
    for rel in files.keys():
        if not rel.endswith('.js') or not files[rel]:
            continue
        text = files[rel].decode('utf-8', 'ignore')
        if ':' not in text:
            continue
        for key, value in iter_string_pairs(text):
            if len(value) <= 200:
                table.setdefault(key, set()).add(value)
    CONST_CACHE[id(files)] = table
    return table


def recover_const_channels(files, samples):
    """试一把「常量键反推」：把归不到名字的表达式里最后那个键，
    拿包里唯一的字符串值兜回来。

    规则只有一条，而且必须写死：同一个键在包里出现两个不同字符串值，就不补。
    宁可列进「没补上」，也不猜——猜错一次，整份清单的可信度就没了。

    返回 {'recovered': [(表达式, 通道名)], 'ambiguous': [(表达式, [候选值…])]}。
    """
    if not samples:
        return {'recovered': [], 'ambiguous': []}
    values = {}
    for rel in files.keys():
        if not rel.endswith('.js') or not files[rel]:
            continue
        text = files[rel].decode('utf-8', 'ignore')
        if ':' not in text:
            continue
        for key, value in CONST_PAIR_RE.findall(text):
            values.setdefault(key, set()).add(value)
    recovered, ambiguous = [], []
    for item in samples:
        expr = item.split(' ', 1)[1] if ' ' in item else item
        key = expr.split('.')[-1].strip()
        found = values.get(key)
        if not found:
            continue
        if len(found) == 1:
            recovered.append((expr, next(iter(found))))
        else:
            ambiguous.append((expr, sorted(found)))
    return {'recovered': recovered, 'ambiguous': ambiguous}


def count_unattributed(files, max_files=12):
    """整个包里有多少注册点的通道名我没解出来。数字，不是形容。"""
    try:
        import jsparse
    except ImportError:
        return None
    names = [rel for rel in files.keys() if rel.endswith('.js') and files[rel]]
    if not names:
        return None
    with_ipc = [rel for rel in names if b'ipcMain' in files[rel]]
    if not with_ipc:
        return {'count': 0, 'samples': [], 'dependency': []}
    with_ipc.sort(key=lambda rel: -len(files[rel] or b''))
    total = 0
    samples = []
    dependency = []
    const_strings = package_const_strings(files)
    for rel in with_ipc[:max_files]:
        text = files[rel].decode('utf-8', 'ignore')
        try:
            tokens = jsparse.tokenize(text)
            objects = parse_object_literals(text)
            found = jsparse.unattributed_registrations(tokens, objects,
                                                      const_strings=const_strings)
        except Exception:
            continue
        for line, expr in found:
            # 第三方依赖里的动态注册（electron-log 那种 `ipcMain.on(channel, …)`，
            # channel 是形参）跟应用自己的空档不是一回事：前者静态永远拿不到，
            # 后者是我该补的。分开计数，别混成一坨吓人。
            if 'node_modules/' in rel:
                dependency.append(f'{rel}:{line} {expr}')
                continue
            total += 1
            if len(samples) < 40:
                samples.append(f'{rel}:{line} {expr}')
    return {'count': total, 'samples': samples, 'dependency': dependency}




def handler_params(tokens, start, end):
    """从处理函数开头取形参名。

    箭头函数 (event, value) => 或 function (event, value) {} 都认。
    取不到就返回空列表——空列表意味着「不假设任何形参脏」，
    比硬塞一个 payload 进去老实。
    """
    i = start
    while i < end and tokens[i].text not in ('(', '{'):
        i += 1
    if i >= end or tokens[i].text != '(':
        return []
    names = []
    depth = 0
    for j in range(i, min(end, len(tokens))):
        text = tokens[j].text
        if text == '(':
            depth += 1
            continue
        if text == ')':
            depth -= 1
            if depth == 0:
                break
            continue
        if tokens[j].kind == 'ident' and depth == 1:
            names.append(text)
    return names


def channel_taint_map(files, max_files=12):
    """第二条口径：外部输入能不能走到危险参数。

    和 channel_sinks（可达性）不是一回事：
      可达性说「这条通道能碰到写文件」——自己拼的路径也算，所以面宽；
      污点说「请求里的东西能到那个参数」——这才是要动手修的那批。
    两个都报，读的人不用猜我到底在说什么。
    """
    try:
        import jsparse
        import jssem
    except ImportError:
        return None
    names = [rel for rel in files.keys() if rel.endswith('.js') and files[rel]]
    if not names:
        return None
    with_ipc = [rel for rel in names if b'ipcMain' in files[rel]]
    if not with_ipc:
        return None
    with_ipc.sort(key=lambda rel: -len(files[rel] or b''))
    out = {}
    for rel in with_ipc[:max_files]:
        text = files[rel].decode('utf-8', 'ignore')
        try:
            tokens = jsparse.tokenize(text)
            objects = parse_object_literals(text)
            defs = jsparse.function_defs(tokens)
            regs = [r for r in jsparse.ipc_registrations(tokens, objects) if r['channel']]
        except Exception:
            continue
        for reg in regs:
            span = reg.get('span')
            if not span and reg.get('target'):
                for item in defs:
                    if item['name'] == reg['target']:
                        span = (item['body_start'], item['body_end'])
                        break
            if not span:
                continue
            try:
                params = handler_params(tokens, span[0], span[1])
                flows = jssem.flows_into_danger(tokens, span[0], span[1], params)
            except Exception:
                continue
            if flows:
                out.setdefault(reg['channel'], set()).update(flows)
    return {name: sorted(set(v)) for name, v in out.items()}


def channel_sinks_map(files, main_rel=None, max_files=12, with_paths=False):
    """每条通道能碰到哪些危险 API：同文件可达 + 跨文件一到两跳。

    真包踩过两次坑，都记在这儿：
    1. 按「最大的 js」挑主文件会挑到 node_modules；抖音的注册点全在
       node_modules/@annie/electron 里，那是它自己的框架，挑它其实没错，
       错在只看一个文件——注册点本来就会分散在好几个文件里。
    2. 所以这里扫「所有含 ipcMain 的 js」，每个文件各自算，再按通道合并。
       文件数封顶 max_files（按大小从大到小），免得在超大包里跑太久。

    返回 {通道: [危险调用名...]}；分析器不在或一个注册点都没找到时返回 None，
    报告里写 null——不写空字典冒充「都没有」。
    """
    try:
        import jsparse
        import jssem
    except ImportError:
        return None

    names = [rel for rel in files.keys() if rel.endswith('.js')]
    if not names:
        return None
    if main_rel is not None and main_rel in names:
        targets = [main_rel]
    else:
        with_ipc = [rel for rel in names if files[rel] and b'ipcMain' in files[rel]]
        if not with_ipc:
            return None
        with_ipc.sort(key=lambda rel: -len(files[rel] or b''))
        targets = with_ipc[:max_files]

    known = set(files.keys())
    const_strings = package_const_strings(files)
    out = {}
    paths = {}
    ast_out = {}
    ast_ambiguous = set()
    ast_supported = True
    reg_at = {}   # 通道 -> '文件:行'，给证据用的注册点位置
    for rel in targets:
        blob = files[rel]
        if not blob:
            continue
        text = blob.decode('utf-8', 'ignore')
        try:
            tokens = jsparse.tokenize(text)
            defs = jsparse.function_defs(tokens)
            objects = parse_object_literals(text)
            regs = [r for r in jsparse.ipc_registrations(tokens, objects, const_strings)
                    if r['channel']]
        except Exception:
            continue
        program = None
        if ast_supported:
            try:
                import jsast
                program = jsast.parse(text)
            except Exception:
                ast_supported = False
        if not regs:
            continue

        # 这个文件 require 到的本地文件，用于跨文件一跳
        other_tokens = {}
        for spec, _imported in jssem.module_aliases(tokens).values():
            target = jssem.resolve_spec(spec, rel, known)
            if not target or target not in files or not files[target]:
                continue
            try:
                other_tokens[target] = jsparse.tokenize(files[target].decode('utf-8', 'ignore'))
            except Exception:
                continue

        for reg in regs:
            found = set()
            span = reg.get('span')
            # 证据里的「位置」优先给**处理函数体**的行号。包里一堆 ipcMain.on
            # 常常挤在同一个 forEach 里，注册点全是同一行——那种位置跳到源码
            # 只能看到一个循环，等于没给。算不出处理函数体的，才退回注册点。
            if reg.get('channel'):
                loc = '%s:%s' % (rel, reg.get('line') or 0)
                if span:
                    try:
                        tok = tokens[span[0]]
                        # 压缩过的包整个文件就几行，行号全是同一个数（实测
                        # obsidian 47 条通道全落在 main.js:66）。所以再带上字符
                        # 偏移，人才能在那一行里找到位置。`@` 后面是偏移。
                        loc = '%s:%s@%s' % (rel, tok.line + 1, tok.start)
                    except (IndexError, AttributeError):
                        pass
                reg_at[reg['channel']] = loc
            if not span and reg.get('target'):
                # 处理函数是按名字传进来的（ipcMain.on('relaunch', relaunch)）：
                # 把那个函数的身子当处理函数体。同一个文件里找不到就算了，不猜。
                # 压缩产物里同名函数不止一个（一堆 f、y、m），取「离注册点最近的
                # 那一个前辈」；前面没有就取后面最近的一个。取错就等于乱认。
                same = [d for d in defs if d['name'] == reg['target']]
                if same:
                    line = reg.get('line') or 0
                    before = [d for d in same if (d.get('line') or 0) <= line]
                    pick = before[-1] if before else same[0]
                    span = (pick['body_start'], pick['body_end'])
            if span:
                found.update(jssem.sinks_in_span(tokens, span[0], span[1]))
                if other_tokens:
                    for _rel, _name, sinks in jssem.cross_file_member_sinks(
                            tokens, span[0], span[1], rel, other_tokens):
                        found.update(sinks)
            reach, hops, vias = jssem.reachable_sinks(
                tokens, defs, list(reg['calls']),
                anchors={'line': reg.get('line') or 0}, with_hops=True)
            for calls in reach.values():
                found.update(calls)
            if program is not None:
                try:
                    import jsast
                    from jssem import DANGER as _DANGER
                    result = jsast.reachable_from_roots(program, list(reg['calls']), _DANGER)
                    if result:
                        ast_out[reg['channel']] = sorted(result)
                        # 路径里带问号 = 经过同名多义（压缩产物里常见）。
                        # 这种结论要单独标出来：它可能是对的，也可能是跟错了身子。
                        if any('?' in step for paths in result.values() for step in paths):
                            ast_ambiguous.add(reg['channel'])
                except Exception:
                    ast_supported = False
            for api, count in hops.items():
                paths.setdefault(reg['channel'], {})[api] = {
                    'hops': count, 'via': vias.get(api, ''),
                    'at': reg_at.get(reg['channel']) or ''}
            if found:
                out.setdefault(reg['channel'], set()).update(found)

    sinks = {name: sorted(apis) for name, apis in out.items()}
    if with_paths:
        # reg_at 单独返回：塞进 paths 会被下游「遍历每条通道的每个 API」的代码
        # 当成一条 API 处理（真的崩过：AttributeError: 'str' object has no 'get'）。
        return sinks, paths, ast_out, sorted(ast_ambiguous), reg_at
    return sinks


def sibling_asar_paths(path, limit=12, depth=3):
    """同一个安装位置里还有哪些 .asar。

    真包踩过：抖音的渲染进程、小组件、托盘各是一个包，而且不在同一个目录
    （8.8.0/resources、8.8.0/tray/resources、8.8.0/game_desktop_widget/resources）。
    只看一个包，等于只看了一栋楼的一层——所以从版本目录往下走三层去找。
    上限 12 个，别在大安装目录上跑太久。
    """
    resources = os.path.dirname(os.path.abspath(path))
    root = os.path.dirname(resources)
    found = []
    seen = {os.path.abspath(path)}
    for current, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ('node_modules', 'locales', 'swiftshader')]
        if current.count(os.sep) - root.count(os.sep) >= depth:
            dirs[:] = []
        for name in sorted(names):
            if not name.endswith('.asar'):
                continue
            candidate = os.path.abspath(os.path.join(current, name))
            if candidate in seen:
                continue
            seen.add(candidate)
            found.append(candidate)
            if len(found) >= limit:
                return found
    return found

def analyse_bundle(path, with_siblings=True):
    """把一个安装位置上的所有 asar 一起扫，通道取并集。

    返回 {'main': 主包报告, 'others': [(路径, 通道数)], 'channels': 并集}。
    没有别的包时 others 为空，行为和单包一致——不改变原有口径，只是多扫几层。
    """
    facts, file_count, total = analyse_asar(path)
    channels = set(facts.get('channels') or [])
    others = []
    if with_siblings:
        for other in sibling_asar_paths(path):
            try:
                other_facts, _n, _b = analyse_asar(other)
            except Exception:
                continue
            other_channels = set(other_facts.get('channels') or [])
            others.append((other, len(other_channels)))
            channels |= other_channels
    return {
        'main': path,
        'main_channels': len(facts.get('channels') or []),
        'others': others,
        'channels': sorted(channels),
        'file_count': file_count,
        'bytes': total,
    }


def build_asar_report(target, facts, file_count, total_bytes, names, evidence,
                      checks, poke_buckets, baseline_obj, merkle=None):
    """asar 路径的 JSON 报告。单独抽出来，好让契约测试直接盯它的顶层键。"""
    report = {
        'schema': SCHEMA_VERSION,
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
        'native_imports': facts['native_imports'],
        'attack_surface': {k: v for k, v in facts['attack_surface'].items() if v},
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
        'fingerprint': fingerprint_of(target, names),
        'sites': all_sites(facts),
        'archive_merkle': merkle,
        # 每条通道能碰到什么；没算出来就是 null，不用空字典冒充「都没有」。
        'channel_sinks': facts.get('channel_sinks'),
        # 每条危险调用是怎么摸到的：处理函数 → 谁 → 谁 → 危险 API
        'channel_sink_paths': facts.get('channel_sink_paths'),
        # 语法树口径的可达性：成员调用、回调传参、别名都能连上
        'channel_sinks_ast': facts.get('channel_sinks_ast'),
        # 软档（同名多义/仅语法树）报出来的 API：**不进结论**，
        # 单独列出来标「这条通道认出来了，能碰到什么没分析」。
        # 每条 sink 结论的凭据：档位、几跳、经过哪些函数名、注册点在哪一行。
        # 摆证据 > 报数字：人看到 at 就能跳过去核，几秒钟的事。
        'channel_sink_evidence': facts.get('channel_sink_evidence'),
        # 这些结论要经过同名多义链，可能是跟错了函数，读的时候要留一分
        'channel_sinks_ambiguous': facts.get('channel_sinks_ambiguous'),
        # 每条危险 API 的来路可信度档（direct/name_confirmed/chain/ambiguous/ast_only）
        'channel_sink_tiers': facts.get('channel_sink_tiers'),
        # 每条通道一份档案：能力标签 + 代码位置 + 证据来源（静态AST/动态探针）
        'channel_profiles': channel_profiles(facts, evidence),
        # 第二条口径：外部输入能到危险参数的通道
        'channel_tainted': facts.get('channel_tainted'),
        # 名字没解出来的注册点数：这是空档，不是零
        'channel_unattributed': facts.get('channel_unattributed'),
        # 卡在什么形状上：几行样例，够人判断该不该往下钻
        'channel_unattributed_samples': facts.get('channel_unattributed_samples'),
        # 试过一次常量反推的结果：唯一的才补，多个值的一律列出来不猜
        'channel_names_recovered': facts.get('channel_names_recovered'),
        # 第三方依赖里的动态注册：静态拿不到，跟「我该补的空档」分开
        'channel_dynamic_in_deps': facts.get('channel_dynamic_in_deps'),
    }
    # 报告自己的指纹在函数里算好：任何调用方拿到的都是完整报告，
    # 不会出现「漏了这个键」的两种形态。
    report['content_digest'] = content_digest(report)
    return report




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
    if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
        # fuzz 抓到过：records 写成字符串、或列表里塞了非字典，都会 .get 崩掉
        raise SystemExit('这不是 REA 的 Evidence 包：records 不是记录列表')
    for record in records:
        result = record.get('normalized_result') or {}
        if 'graph' in result:
            # 顺手把能力面也算上：Evidence 给了精确的 handler 行列，切出来的
            # 处理函数体比字符串级括号配对准；算不出来就留空，不硬猜。
            try:
                result['capability'] = capability_from_evidence(result)
            except (OSError, ValueError, KeyError, TypeError):
                result['capability'] = {}
            return result
    raise SystemExit('证据里没有应用图，可能不是 analyze-javascript-application 的输出')


def loc(evidence):
    value = ((evidence or {}).get('location') or {}).get('value') or {}
    if value.get('kind') == 'source-range':
        return f"{value['source']}:{value['start']['line'] + 1}"
    if value.get('kind') == 'artifact-path':
        return value.get('path', '?')
    return '?'


# 报告 JSON 的顶层键白名单。多一个键就红——「别把 durable 写进报告」这条
# 纪律不能只写在 README 里，得有个东西替我们盯着。
# 先留一份有序的清单再转 frozenset：frozenset 会把重复项吃掉，之前白名单里
# 'sites'/'archive_merkle'/'content_digest' 就各写了两遍，谁也没发现。
REPORT_TOP_LEVEL_KEY_LIST = (
    'schema', 'version', 'mode', 'subject', 'files', 'bytes',
    'channels', 'exposes', 'dynamic', 'native_files', 'native_imports', 'obfuscation',
    'unique_names', 'evidence', 'confidence', 'confidence_semantics',
    'limits', 'runtime', 'poke', 'web_preferences', 'attack_surface', 'baseline',
    'fingerprint', 'sites', 'archive_merkle', 'content_digest',
    'channel_sinks', 'channel_sink_paths', 'channel_sinks_ast',
    'channel_sinks_ambiguous', 'channel_sink_tiers', 'channel_profiles',
    'channel_sink_evidence',
    'channel_tainted', 'channel_unattributed', 'channel_unattributed_samples',
    'channel_names_recovered', 'channel_dynamic_in_deps',
)
REPORT_TOP_LEVEL_KEYS = frozenset(REPORT_TOP_LEVEL_KEY_LIST)


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
    UNSUPPORTED = 'unsupported'   # 这个内核根本没这条路（拿不到刷新目录的办法）
    FAILED = 'failed'


DURABLE_YES = 'yes'
DURABLE_NO = 'no'
DURABLE_UNKNOWN = 'unknown'


# Windows 不给目录开普通文件句柄，但带 FILE_FLAG_BACKUP_SEMANTICS 能拿到目录句柄，
# FlushFileBuffers 接受目录句柄。这是 Win32 自己的语义，不需要装 pywin32——
# ctypes 就在标准库里。以前这里直接返回 UNSUPPORTED，等于把一个能做到的事
# 记成「这套系统没有这个能力」，让 durable 永远停在 unknown。
_WIN_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
# 开目录句柄要 GENERIC_WRITE，不是 GENERIC_READ：FlushFileBuffers 要求句柄带写权限，
# 拿读权限去刷会被直接拒（实测 ERROR_ACCESS_DENIED = 5，不是刷不动，是不许你刷）。
# 能有这权限是因为同一目录里刚建过临时文件——没这个权限的目录，写那一步就已经失败了。
_WIN_GENERIC_WRITE = 0x40000000
_WIN_SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004
_WIN_OPEN_EXISTING = 3
_win_fsync_api = None


def _windows_dir_flusher():
    """取出 kernel32 里的三个函数，取不到就返回 None（那才是真的 UNSUPPORTED）。"""
    global _win_fsync_api
    if _win_fsync_api is not None:
        return _win_fsync_api or None
    try:
        import ctypes
        from ctypes import wintypes
    except (ImportError, ValueError):     # 标准库里没有 ctypes
        _win_fsync_api = False
        return None
    try:
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        create, flush, close = (kernel32.CreateFileW,
                                kernel32.FlushFileBuffers,
                                kernel32.CloseHandle)
    except (AttributeError, OSError):     # 不是 NT 内核
        _win_fsync_api = False
        return None

    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                       wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    flush.argtypes = [wintypes.HANDLE]
    flush.restype = wintypes.BOOL
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL

    _win_fsync_api = (create, flush, close, ctypes.c_void_p(-1).value)
    return _win_fsync_api


def _fsync_dir_windows(directory):
    """Windows 上刷目录。返回 FsyncResult。

    OK 只说明内核收下了这批目录元数据——硬件缓存、磁盘自己的写缓存都不在
    承诺里；POSIX 上的 fsync 也只管到这一层，两边的保证同宽，所以这里
    敢报 yes。
    """
    api = _windows_dir_flusher()
    if api is None:
        return FsyncResult.UNSUPPORTED
    create, flush, close, invalid = api
    handle = create(directory, _WIN_GENERIC_WRITE, _WIN_SHARE_ALL, None,
                    _WIN_OPEN_EXISTING, _WIN_FILE_FLAG_BACKUP_SEMANTICS, None)
    if not handle or handle == invalid:
        # 句柄开不出来（权限、只读卷、被占用）：有能力但没成，不是没有能力。
        return FsyncResult.FAILED
    try:
        return FsyncResult.OK if flush(handle) else FsyncResult.FAILED
    finally:
        close(handle)


def _fsync_dir(directory):
    """替换之后刷一次目录，让 rename 真正落到盘上。返回 FsyncResult。

    UNSUPPORTED 不等于 FAILED：前者是「这套系统没这个能力」，后者是「有这能力但没成功」。
    混成一个 None/falsy，调用方迟早把未知当失败，或者把未知当成功。
    """
    if os.name == 'nt':
        return _fsync_dir_windows(directory)
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


def stamp_of(ts):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))


def _age_text(seconds):
    """把年龄写成话。回拨和前跳都不直接打印离谱数字。"""
    if seconds is None:
        return '时间未知'
    if seconds < -60:
        return '时间异常（文件时间比现在还晚，可能时钟回拨）'
    if seconds < 0:
        return '刚刚'
    if seconds < 3600:
        return f'{int(seconds // 60)} 分钟前'
    if seconds < 86400:
        return f'{seconds / 3600:.1f} 小时前'
    if seconds < 365 * 86400:
        return f'{seconds / 86400:.1f} 天前'
    return '时间过久（启发式：超过一年就会落这里——可能是时钟前跳，也可能是正常旧文件）'


def inspect_leftovers(path):
    """看一眼这个报告旁边有没有崩溃残留。只摆事实，不下结论。

    不下结论的原因：`.bak` 是新版写完之后才删的，存在副本时 target 可能已经是新版、
    也可能还是旧版——光看文件判断不出来，猜错会把完整的新报告换回旧版。
    但「判断不了」不等于「什么也不给」：把 target 的大小、修改时间、以及它和副本
    谁新谁旧摆出来，人一眼就能判。
    """
    directory = os.path.dirname(os.path.abspath(path)) or '.'
    basename = os.path.basename(path)
    target = os.path.join(directory, basename)

    def stat_of(p):
        try:
            st = os.stat(p)
            return {'bytes': st.st_size, 'mtime': st.st_mtime}
        except OSError:
            return None

    target_stat = stat_of(target)
    result = {'target_exists': target_stat is not None,
              'target_bytes': target_stat['bytes'] if target_stat else None,
              'target_mtime_text': (stamp_of(target_stat['mtime'])
                                    if target_stat else None),
              'backups': [], 'failed': []}
    try:
        names = os.listdir(directory)
    except OSError:
        return result

    for name in names:
        stamp = _ours(name, basename)
        if stamp is None:
            continue
        full = os.path.join(directory, name)
        info = stat_of(full)
        created = int(stamp) / 1000.0
        entry = {
            'path': full,
            'bytes': info['bytes'] if info else None,
            'age_text': _age_text(time.time() - created),
            'created_from': '文件名里的时间戳',
            'mtime_text': stamp_of(info['mtime']) if info else None,
        }
        if target_stat and info:
            # 两边时间源不同：副本用文件名时间戳，target 只有 mtime。
            # 所以这只是线索，不是可采信的结论——输出里也要这么写。
            entry['relation'] = ('副本更晚' if created > target_stat['mtime']
                                 else '副本不晚于 target')
            entry['relation_basis'] = '不同源比较（副本：文件名时间戳；target：mtime），仅作线索'
        elif info:
            # target 不在，就没有「新旧关系」可言；这一栏干脆不出现，
            # 免得在布尔语义的列里放一句「无从比较」。
            entry['relation'] = None
            entry['relation_basis'] = None
        else:
            entry['relation'] = None
            entry['relation_basis'] = None
        if name.endswith('.bak'):
            result['backups'].append(entry)
        else:
            result['failed'].append(entry)
    return result


def render_leftovers(report, path):
    lines = [f'# 崩溃残留检查：{path}', '']
    if not report['target_exists']:
        # target 不在，就没有「对比」可言。整张表退化成副本清单，
        # 不摆半张只有一侧的表——那会让人以为另一侧的值只是没显示。
        lines.append('- **目标文件不存在。** 下面列出仅存的副本，先看内容，先别删。')
        if not report['backups'] and not report['failed']:
            lines.append('- 也没有副本。这份报告确实什么都没留下。')
            return '\n'.join(lines) + '\n'
        for label, items in (('备份副本', report['backups']),
                             ('替换失败现场', report['failed'])):
            for item in items:
                lines.append(f"- {label}：`{item['path']}`（{item['bytes']} 字节，"
                             f"{item['age_text']}，按文件名里的时间戳）")
        lines += ['', '**不自动还原，也不替你判断。** 副本存在只说明「上次可能崩在'
                  '替换与清理之间」；没有 target 可以对比，就只能由人看内容定。']
        return '\n'.join(lines) + '\n'
    lines.append(f"- 目标：{report['target_bytes']} 字节，改动时间 "
                 f"{report['target_mtime_text']}（按文件修改时间）")
    if not report['backups'] and not report['failed']:
        lines.append('- 没有发现 `.bak` / `.failed` 残留。')
        return '\n'.join(lines) + '\n'

    for label, items in (('备份副本', report['backups']),
                         ('替换失败现场', report['failed'])):
        for item in items:
            line = (f"- {label}：`{item['path']}`（{item['bytes']} 字节，"
                    f"{item['age_text']}，按文件名里的时间戳）")
            if item.get('relation'):
                line += f"；{item['relation']}"
                if item.get('relation_basis'):
                    line += f"（{item['relation_basis']}）"
            line += '）'
            lines.append(line)

    lines += ['', '**不会自动还原，也不替你判断。** 上面只给事实：两份文件的大小和'
              '各自的时间。谁新谁旧只是线索——两边时间来源不同，`.bak` 的修改时间还可能被 '
              'copy2 带成旧值。',
              '看过内容、确认该留哪一份，再自己动手；确认不需要的可以删掉。']
    return '\n'.join(lines) + '\n'


def _win_long(path):
    """Windows 上超过 260 字符的路径要加扩展前缀，否则 create/open 直接报 206。

    只改传进去的路径，不改调用方看到的名字。
    """
    if os.name != 'nt':
        return path
    full = os.path.abspath(path)
    if len(full) < 240 or full.startswith('\\\\?\\'):
        return full
    if full.startswith('\\\\'):
        return '\\\\?\\UNC\\' + full[2:]
    return '\\\\?\\' + full


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

    raw_target = _win_long(path)
    directory = os.path.dirname(os.path.abspath(path)) or '.'
    long_directory = os.path.dirname(raw_target)
    basename = os.path.basename(path)
    try:
        os.makedirs(long_directory, exist_ok=True)
    except OSError as exc:
        raise OutputError(_output_kind(exc), f'目标目录建不出来：{directory}\n{exc}')

    warnings = []
    _removed, kept = clean_stale_backups(directory, basename)
    if kept:
        warnings.append(f'发现 {len(kept)} 个未处理的备份副本，可能是之前崩在中间留下的；'
                        f'没自动恢复，请人工确认（第一个：{kept[0]}）')

    handle, temp_path = tempfile.mkstemp(dir=long_directory,
                                        prefix=WRITE_TMP_PREFIX, suffix='.part')
    stamp = int(time.time() * 1000)
    backup = os.path.join(long_directory, f'.{basename}.{stamp}.{uuid.uuid4().hex[:8]}.bak')
    target_path = raw_target
    had_old = os.path.exists(target_path)
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
                shutil.copy2(target_path, backup)
            except OSError as exc:
                raise OutputError(_output_kind(exc),
                                  f'备份旧报告失败，所以没有替换：{path}\n{exc.strerror or exc}')

        try:
            os.replace(temp_path, target_path)
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
            # 这台机器上根本没有刷目录的办法。报 unknown：不阻塞，也不冒充知道。
            durable = DURABLE_UNKNOWN
            warnings.append('这台机器上拿不到刷目录的办法，无法确认持久性：文件已是新版，'
                            '崩溃后是否回退取决于文件系统。')

        else:
            raise AssertionError('未处理的 FsyncResult：' + repr(fsync_state))

        if os.name == 'nt' and not _windows_hint_shown:
            globals()['_windows_hint_shown'] = True
            warnings.append('Windows 上目录刷盘走 FlushFileBuffers；只读卷和网络盘没实测过，'
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
    # 交叉档位也是聚合：一个 strong 盖住「哪两个文件」的细节，
    # 想引用这一档，得能点回 corroboration_basis。
    {'field': 'corroboration_level', 'detail': 'corroboration_basis',
     'must_not': 'use_corroboration_level_alone'},
]

# evidence 里每个名字允许出现的字段。不在这张白名单、也不在 AGGREGATE_FIELDS 里的新字段，
# 一律当成「疑似聚合字段」报出来——这是正向扫描，不是靠字段名字长得像。
EVIDENCE_FIELDS = {
    'sources', 'strength', 'where', 'actions', 'primary_action',
    'corroboration', 'corroborated', 'independent_pairs',
    'runtime_where', 'corroboration_level', 'corroboration_basis', 'where_all',
    'refutes_if', 'enum_proof', 'harvest_grade', 'capability',
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


def crosscheck_layers(runtime_names, static_names):
    """静态和动态的名字对账，分三层。

    动态不是用来替代静态的，是用来印证静态的：
    - both         静态认得、运行时也注册了 → 两条独立的路对上，最可信
    - static_only  静态认得、运行时没看到 → 可能懒加载/条件分支没触发，不是错
    - runtime_only 运行时注册了、静态没认出 → 静态的漏（拼装名、动态注册、加壳）
    """
    runtime = set(runtime_names or ())
    static = set(static_names or ())
    return {
        'both': sorted(runtime & static),
        'static_only': sorted(static - runtime),
        'runtime_only': sorted(runtime - static),
    }


def render_runtime(probe, static_channels=None):
    """把探针跑出来的东西并进来，按「双向印证 / 仅静态 / 仅动态」分层。

    动态在这里的角色是**印证**静态，不是替代它：静态认得、运行时也注册的，
    才敢说这条路是实的；只有静态认得的，写「没触发」；只有运行时看到的，
    才是静态真漏了的。
    """
    out = ['', '## 跑起来之后看见的（动态印证静态）', '']
    if probe.get('error'):
        out.append(f'- 没跑起来：{probe["error"]}')
        out.append('')
        return out
    handlers = probe.get('handlers') or []
    listeners = probe.get('listeners') or []
    runtime = list(handlers) + list(listeners)
    out.append(f'- 主进程上挂着 {len(handlers)} 条 invoke 通道、{len(listeners)} 条 listener')

    if static_channels is not None:
        layers = crosscheck_layers(runtime, static_channels)
        out.append('')
        out.append(f"  - **双向印证**：{len(layers['both'])} 条（静态认得，运行时也注册了）")
        for name in layers['both']:
            out.append(f'    - `{name}`')
        out.append(f"  - **仅静态**：{len(layers['static_only'])} 条（静态认得，这次没跑起来）")
        for name in layers['static_only'][:10]:
            out.append(f'    - `{name}`')
        if len(layers['static_only']) > 10:
            out.append(f'    - …还有 {len(layers["static_only"]) - 10} 条')
        out.append(f"  - **仅动态**：{len(layers['runtime_only'])} 条（运行时注册了，静态没认出）")
        for name in layers['runtime_only'][:10]:
            out.append(f'    - `{name}`')
        if len(layers['runtime_only']) > 10:
            out.append(f'    - …还有 {len(layers["runtime_only"]) - 10} 条')
        if layers['runtime_only']:
            out.append('- 仅动态那批是静态的漏：可能是名字拼出来的、动态注册的，或者加壳读不出')
        if layers['static_only']:
            out.append('- 仅静态那批不是错：懒加载、条件分支没走到，都会这样；别读成「不存在」')
    else:
        for name in handlers:
            out.append(f'  - `{name}`')

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


def parse_pe_bytes(data):
    """读 PE 的导入表，纯字节入口（fuzz 用，也方便单测）。坏输入 SystemExit，别崩。

    只回答一件事：这个模块引了外头哪些函数。
    """
    if len(data) < 2 or data[:2] != b'MZ':
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


def read_pe_imports(path):
    """读 PE 的导入表。只回答一件事：这个模块引了外头哪些函数。"""
    with open(path, 'rb') as fh:
        data = fh.read()
    return parse_pe_bytes(data)


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


# 打捞出来的候选分四档——这是「一堆线索」和「能用的清单」之间的那道分界。
# 只有第一档是通道；后三档是线索，强度依次往下：
#   channel  : 和静态看见的通道名对上了，不是线索，就是它本身
#   near-ipc : 出现在提到 IPC 的文件里（离调用多远都算，名字常躺在表里）
#   clustered: 同前缀 ≥3 个成簇出现，像一张名字表
#   stray    : 零星、只在别的文件里出现，最可能是噪音


def grade_harvested(files, harvested, channel_names):
    """给每个候选定一档。返回 {名字: 档位}。

    只用能机械判的事实：是否与通道名相同、是否出现在含 IPC 的文件里、
    同前缀的候选有几个。不做语义猜测——猜错了比不分档更坏。
    """
    ipc_files = set()
    for rel, blob in files.items():
        if rel.endswith(TEXT_EXT) and any(token in blob for token in
                                         (b'ipcMain', b'ipcRenderer', b'contextBridge')):
            ipc_files.add(rel)
    counts = {}
    for name in harvested:
        prefix = name.split(':', 1)[0] if ':' in name else ''
        counts[prefix] = counts.get(prefix, 0) + 1
    grades = {}
    for name, (where, _kind) in harvested.items():
        if name in channel_names:
            grades[name] = 'channel'
            continue
        if where.split(':', 1)[0] in ipc_files:
            grades[name] = 'near-ipc'
            continue
        prefix = name.split(':', 1)[0] if ':' in name else ''
        grades[name] = 'clustered' if counts.get(prefix, 0) >= 3 else 'stray'
    return grades


def analyse_asar(path, allow_eval=True, max_passes=1, events=None):
    """扫一个 asar。

    events 传 jsevents.EventBus 时，过程会被录成事件流（--events-out）；
    传 None 时一行事件都不发，行为和以前完全一样。
    """
    header, files = read_asar(path)
    started_at = time.monotonic()
    # 文件表是开着源文件按需切的，用完得自己关。Windows 上不关，
    # 这个包删都删不掉。
    try:
        if events is not None:
            events.emit('lifecycle', {
                'stage': 'start',
                'input': os.path.basename(path),
                'size': files.total_bytes() if hasattr(files, 'total_bytes') else None,
            }, phase='coarse')
        facts = scan_asar(files, allow_eval=allow_eval, max_passes=max_passes,
                          events=events)
        recovered = scan_sourcemaps(files)
        if recovered:
            extra = scan_asar(recovered)
            for key in ('exposes', 'handlers', 'invokes', 'dynamic', 'preloads', 'obfuscation'):
                merged = set(facts[key]) | set(extra[key])
                facts[key] = sorted(merged)
            facts['scanned'] += extra['scanned']
        facts['recovered'] = sorted(recovered)
        facts['harvested'] = harvest_strings(files)
        facts['harvest_grades'] = grade_harvested(
            files, facts['harvested'], set(facts['channels']))
        facts['archive_merkle'] = archive_merkle(files)
        try:
            collected = channel_sinks_map(files, with_paths=True)
        except TypeError:
            collected = None
        # 分析器不在、或者一个注册点都没找到时是 None：别当场解包炸掉，
        # 报告里写 null 才是老实的语义（「没分析」不等于「没有」）。
        if collected is None:
            sinks, sink_paths, ast_sinks, ast_amb = None, None, None, []
            reg_at = {}
        else:
            sinks, sink_paths, ast_sinks, ast_amb, reg_at = collected
        facts['channel_sinks_ambiguous'] = ast_amb
        facts['channel_sinks_ast'] = ast_sinks
        facts['channel_sinks'] = sinks
        facts['channel_sink_paths'] = sink_paths
        # 全部档位都报，但每一条都带「凭什么」。
        #
        # 0.97.0 曾把软档（ambiguous / ast_only）整块砍掉，精确率好看但漏了 9 条
        # 人工核过的真阳性——那是拿漏报换数字，不做。
        # 现在的做法：档位照报，另外给每条结论配一份证据（档位、几跳、经过哪些
        # 函数名、注册点在哪个文件哪一行）。人看到 `at` 就能跳到源码，几秒钟判断
        # 这条结论对不对——这才是「摆证据，减少复核成本」。
        _tier_src = ast_sinks if ast_sinks is not None else sinks
        if _tier_src is not None:
            tiers = {ch: {api: sink_tier(facts, ch, api) for api in apis}
                     for ch, apis in _tier_src.items() if apis}
            facts['channel_sink_tiers'] = tiers if tiers else None
            evidence = {}
            for ch, api_tiers in tiers.items():
                paths_for_ch = sink_paths.get(ch) or {}
                fallback_at = (reg_at or {}).get(ch) or ''
                for api, tier in api_tiers.items():
                    step = paths_for_ch.get(api) or {}
                    evidence.setdefault(ch, {})[api] = {
                        'tier': tier,
                        'hops': step.get('hops'),
                        'via': step.get('via') or '',
                        # 没有路径的档位（name_confirmed 这种）也要给出注册点，
                        # 不然人得自己去全包里找——那就不叫「减少复核成本」了。
                        'at': step.get('at') or fallback_at,
                    }
            facts['channel_sink_evidence'] = evidence if evidence else None
        else:
            facts['channel_sink_tiers'] = None
            facts['channel_sink_evidence'] = None
        facts['channel_tainted'] = channel_taint_map(files)
        unattr = count_unattributed(files)
        facts['channel_unattributed'] = None if unattr is None else unattr['count']
        facts['channel_unattributed_samples'] = None if unattr is None else unattr['samples']
        facts['channel_dynamic_in_deps'] = None if unattr is None else len(unattr['dependency'])
        recovered = None if unattr is None else recover_const_channels(files, unattr['samples'])
        facts['channel_names_recovered'] = recovered
        total = files.total_bytes()
        if events is not None:
            # lifecycle.done 必须是最后一条，统计字段要和报告顶层逐项对得上
            # （设计守则 4：实时视图和最终报告必须可对账）。
            tiers = facts.get('channel_sink_tiers') or {}
            by_tier = {}
            channel_tiers = {}
            for ch, ch_tiers in tiers.items():
                vals = [t for t in (ch_tiers or {}).values() if t]
                for tier in vals:
                    by_tier[tier] = by_tier.get(tier, 0) + 1
                if vals:
                    # 一条通道可能挂着多个档位，取最强的那个当它的代表档
                    channel_tiers[ch] = min(
                        vals, key=lambda x: (SINK_TIER_ORDER.index(x)
                                             if x in SINK_TIER_ORDER else 99))
            sink_src = facts.get('channel_sinks_ast') or facts.get('channel_sinks') or {}
            # 预警要在 done 之前发（design 3.3：discovery 先于引用它的 warning，
            # 而 done 必须是最后一条）。预警只是「提醒你看」，不改 tier。
            try:
                import jswarn
                for warn in jswarn.build_warnings(facts):
                    events.emit('warning', warn, phase='report')
            except Exception:  # noqa: BLE001 —— 预警引擎炸了不能把扫描带崩
                pass
            events.emit('lifecycle', {
                'stage': 'done',
                'input': os.path.basename(path),
                'exit_code': 0,
                'channels': len(facts['channels']),
                'sinks': sum(len(v) for v in sink_src.values() if v),
                'by_tier': by_tier,
                # 每条通道的代表档：实时页面靠它上色，缺了就只能画横线
                'channel_tiers': channel_tiers,
                'unresolved': len(facts.get('dynamic') or []),
                'elapsed_ms': int((time.monotonic() - started_at) * 1000),
            }, phase='report')
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
    parser.add_argument('input', nargs='?', help='.asar 包、REA 的 Evidence JSON，或 dll/exe')
    parser.add_argument('--version', action='version', version=f'ipcsurface {__version__}')
    parser.add_argument('-o', '--out', help='写到文件，不给就打到标准输出')
    parser.add_argument('--recover', metavar='REPORT',
                        help='检查某个报告旁边的崩溃残留（.bak/.failed），只报告不自动还原')
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
    parser.add_argument('--precise', action='store_true',
                        help='用 tree-sitter 精查层补一列（跨文件/类方法）。需要 pip install ipcsurface[precise]')
    parser.add_argument('--events-out', metavar='JSONL',
                        help='把扫描过程录成事件流（JSONL，append-only）。不给就不发事件，行为和以前完全一致')
    parser.add_argument('--live', action='store_true',
                        help='把扫描过程画到终端（ANSI，80 列）。借来档一律画灰的')
    parser.add_argument('--serve', type=int, metavar='PORT',
                        help='起一个本地只读页面（SSE + 快照），扫完不退出，Ctrl+C 结束')
    parser.add_argument('--max-buffer', type=int, default=50000, metavar='N',
                        help='页面在内存里留多少条事件用于刷新/断线补发，默认 50000；0 = 一条不留')
    parser.add_argument('--webhook', metavar='URL',
                        help='把 high 及以上的预警 POST 到这个地址（失败不重试、不阻塞扫描）')
    parser.add_argument('--screenshot', metavar='PNG',
                        help='扫完截一张页面图（要本机有 Edge/Chrome；没有就跳过，不算失败）')
    parser.add_argument('--replay', metavar='JSONL',
                        help='不扫描，回放一份事件流（配 --live / --serve 用）')
    parser.add_argument('--replay-speed', type=float, default=1.0,
                        help='回放倍速，默认 1.0 按录制节奏；0 = 全速')
    args = parser.parse_args(argv)
    server = None   # --serve 起的页面，只有 asar 那条分支会赋值

    # 回放：不需要 asar，直接把录下来的事件喂给渲染器/页面。
    # 前端的行为必须和实时一致——这是它唯一的 e2e 测法。
    if args.replay:
        import jsevents
        bus = jsevents.EventBus(None, scan_id='replay')
        renderer = None
        if args.live:
            jsevents.enable_ansi()
            renderer = jsevents.TerminalRenderer(sys.stderr)
            bus.add_listener(renderer.on_event)
        if args.serve:
            server = jsevents.EventServer(bus, host='127.0.0.1',
                                          port=args.serve,
                                          max_events=args.max_buffer).start()
            print(f'回放页面：{server.url}', file=sys.stderr)
        sent = jsevents.replay(args.replay, bus, speed=args.replay_speed)
        print(f'回放了 {sent} 条事件', file=sys.stderr)
        if renderer is not None:
            renderer.paint()
        if server is not None:
            print(f'回放页面：{server.url}（Ctrl+C 退出）', file=sys.stderr)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.stop()
        return 0

    if args.recover:
        report = inspect_leftovers(args.recover)
        print(render_leftovers(report, args.recover), end='')
        return 0
    if not args.input:
        parser.error('要给一个输入（--recover 模式下不用）')

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
        # 实时层：--events-out 录文件、--live 画终端、--serve 起页面，三个都能单独用。
        # 都不给时 bus 是 None，全程零开销。
        bus = None
        renderer = None
        server = None
        if (args.events_out or args.live or args.serve
                or args.webhook or args.screenshot):
            import jsevents
            # scan_id 用输入文件的 sha256：和报告 fingerprint.input_sha256 同一个值，
            # 事件流和报告能直接对上。这是顺序读一遍文件，只在开实时时付这个开销。
            bus = jsevents.EventBus(
                args.events_out or None,
                scan_id='sha256:' + (input_sha256(args.input) or ''))
            if args.live:
                jsevents.enable_ansi()
                renderer = jsevents.TerminalRenderer(sys.stderr)
                bus.add_listener(renderer.on_event)
            if args.serve:
                server = jsevents.EventServer(bus, host='127.0.0.1',
                                              port=args.serve,
                                              max_events=args.max_buffer).start()
                print(f'实时页面：{server.url}', file=sys.stderr)
            elif args.screenshot:
                # 只截图：也要**扫描前**就把 server 建好，否则事件发完了没人收，
                # 画面里就是 0 条通道。
                server = jsevents.EventServer(bus, host='127.0.0.1', port=0,
                                              max_events=max(args.max_buffer, 1000)).start()
            if args.webhook:
                sink = jsevents.WebhookSink(args.webhook)
                bus.add_listener(sink)
                print(f'预警推送到 {args.webhook}（只推 high 及以上）', file=sys.stderr)
        try:
            facts, count, total = analyse_asar(
                args.input, allow_eval=not args.no_eval,
                max_passes=6 if args.deep_restore else 1, events=bus)
        finally:
            if bus is not None:
                bus.close()
            if renderer is not None:
                # 最后一面留在屏幕上，接着就是报告本身
                renderer.paint()
        # precise：tree-sitter 精查层，opt-in，装不上就降级不硬撑
        if args.precise:
            try:
                import precise_engine
                facts['precise_sinks'] = precise_engine.analyse_asar_precise(args.input)
            except SystemExit:
                facts['precise_sinks'] = None
            except Exception:
                facts['precise_sinks'] = None
        findings = audit_asar(facts)
        names = {n for n, _ in facts['handlers']} | {n for n, _ in facts['invokes']}
        probe_data = load_probe(args.runtime) if args.runtime else None
        poke_data = load_poke(args.poke) if args.poke else None
        if args.format == 'json':
            checks = runtime_crosscheck(probe_data, names)
            evidence = channel_sources(facts, probe=probe_data)
            poke_buckets = classify_poke(poke_data) if poke_data else None
            report = build_asar_report(
                args.input, facts, count, total, names, evidence,
                checks, poke_buckets, load_baseline(args.baseline)
                if args.baseline else None,
                merkle=facts.get('archive_merkle'))
            text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
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

    # 只有 -o 那条路会写盘，也就只有那条路算得出持久化状态；
    # 不给 -o 也得有个值，不然下面读它直接崩（真包跑出来的）。
    undurable = False
    unknown = False
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

    # --screenshot：server 在扫描前就建好了（没 --serve 时是临时端口），直接用它截。
    if args.screenshot and server is not None:
        import jsevents as _js
        # 走服务端渲染的 /static.html：headless 浏览器不等 JS，用 / 截出来是白页。
        ok, info = _js.screenshot(server.url + 'static.html', args.screenshot)
        print(('截图：' + info) if ok else ('截图跳过：' + info), file=sys.stderr)
        if not args.serve:
            # 临时页面：截完就关，后面不该继续挂着
            server.stop()
            server = None

    # --serve：报告已经打完了，页面留着给人看。Ctrl+C 结束。
    if server is not None:
        print(f'实时页面：{server.url}（Ctrl+C 退出）', file=sys.stderr)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.stop()

    return 0


if __name__ == '__main__':
    sys.exit(main())