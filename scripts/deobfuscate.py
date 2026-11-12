"""obfuscator.io 字符串数组还原：把混淆里藏着的字符串解出来，再喂回扫描。

背景：bilibili 的 main/index.js 用了 obfuscator.io 最高档混淆——连 `ipcMain` 都被
换成 `_0x...`，字符串全编码进一个数组，用 base64 变体 + RC4 解密。静态扫描按名字
匹配，天然扫不到，最后只认出 1 条还来自第三方库。

这里做的是「解混淆的第一步」：还原字符串数组。
1. 找数组函数（函数体里有一个大字符串数组，且自覆盖）；
2. 找解码函数（函数体里有 `+0x100` 的 RC4 S 盒）；
3. 找头部洗牌 IIFE（`while(!![])` + `push(shift())`）；
4. 找所有调用点 `别名(0xIDX, 'KEY')`；
5. 用 Node 跑一遍，把每个调用解成实际字符串。

需要 node（跑解码逻辑用）；没有 node 就跳过，报「没解」，不猜。

用法：
    python scripts/deobfuscate.py <混淆的 .js 文件或 .asar> [--json out.json]

输出：解出的字符串去重列表，以及其中「像通道名」的那些。
"""
import argparse
import codecs
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _func_body(src, name):
    """按函数名取完整函数体（括号匹配）。"""
    i = src.find('function ' + name + '(')
    if i < 0:
        return None
    j = src.find('{', i)
    if j < 0:
        return None
    depth = 0
    for k in range(j, len(src)):
        if src[k] == '{':
            depth += 1
        elif src[k] == '}':
            depth -= 1
            if depth == 0:
                return src[i:k + 1]
    return None


def find_array_function(src):
    """找返回大字符串数组、且自覆盖的函数。返回 (名字, 函数体)。"""
    for m in re.finditer(r'function ([A-Za-z_$][\w$]*)\s*\(\s*\)\s*\{', src):
        name = m.group(1)
        body = _func_body(src, name)
        if not body:
            continue
        # 函数体里有一大串 '\x..' 字符串，且自己重新赋值自己（自覆盖）
        if body.count("'\\x") < 50:
            continue
        if not re.search(r'\b' + re.escape(name) + r'\s*=\s*function', body):
            continue
        return name, body
    return None, None


def find_decode_function(src):
    """找解码函数：函数体里有 RC4 的 0x100 循环 + base64 解码。"""
    for m in re.finditer(r'function ([A-Za-z_$][\w$]*)\s*\([^)]{0,80}\)\s*\{', src):
        name = m.group(1)
        body = _func_body(src, name)
        if not body:
            continue
        if '0x100' in body and '0x40' in body and 'decodeURIComponent' in body:
            return name, body
    return None, None


def find_shuffle(src, array_fn):
    """找头部洗牌 IIFE：它调用数组函数，并做 push(shift()) 循环。"""
    if not array_fn:
        return None
    # 形如 (function(e,f){...}(ARRAYFN,0xCHECKSUM))
    for m in re.finditer(r'\(function\s*\([^)]{0,40}\)\s*\{', src):
        start = m.start()
        depth = 0
        j = src.find('{', start)
        for k in range(j, len(src)):
            if src[k] == '{':
                depth += 1
            elif src[k] == '}':
                depth -= 1
                if depth == 0:
                    end = src.find(';', k)
                    seg = src[start:end + 1 if end > 0 else k + 1]
                    if array_fn in seg and 'shift' in seg:
                        return seg
                    break
    return None


def _match_paren(src, start):
    """从 start 处的 '(' 开始，括号匹配到对应的 ')'，返回整段。"""
    depth = 0
    for k in range(start, len(src)):
        if src[k] == '(':
            depth += 1
        elif src[k] == ')':
            depth -= 1
            if depth == 0:
                return src[start:k + 1]
    return None


def collect_function_bodies(src, names):
    """递归提取函数定义，包括被依赖的其它函数。

    混淆里调用点走的不一定是解码函数本身，可能是好几层包装（每层换个 `_0x..` 名字）。
    与其猜哪层是包装，不如从调用点出发，把它碰到的函数定义全捞出来。
    """
    found = {}
    queue = list(names)
    while queue:
        name = queue.pop()
        if name in found:
            continue
        body = _func_body(src, name)
        if not body:
            continue
        found[name] = body
        for m in re.finditer(r'\b(_0x[0-9a-f]+)\s*\(', body):
            dep = m.group(1)
            if dep not in found:
                queue.append(dep)
    return found


def find_all_calls(src):
    """找所有「第一个实参是 0x 数字、第二个是 \\x 字符串」的调用。

    不限制函数名：混淆里每层包装都换个名字，靠名字筛会漏。
    """
    calls = []
    seen = set()
    for m in re.finditer(r'\b([A-Za-z_$][\w$]*)\(\s*(0?x[0-9a-f]+|-0x[0-9a-f]+)\s*,\s*'
                         r"(?:'((?:\\x[0-9a-f]{2})+)'|\"((?:\\x[0-9a-f]{2})+)\")", src):
        args = _match_paren(src, src.find('(', m.start()))
        if not args:
            continue
        expr = m.group(1) + args          # 函数名 + 参数，别丢函数名
        if expr in seen:
            continue
        seen.add(expr)
        calls.append([m.group(1), expr])
    return calls


def _run_node(parts):
    """把几段 JS 拼起来喂给 Node 跑，返回 (字符串列表, 错误)。"""
    text = '\n'.join(parts)
    fd, path = tempfile.mkstemp(suffix='.js')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write(text)
        run = subprocess.run(['node', path], capture_output=True, text=True,
                             encoding='utf-8', errors='replace', timeout=90)
        if run.returncode != 0:
            return [], (run.stderr or '')[:500]
        return json.loads(run.stdout or '[]'), ''
    except subprocess.TimeoutExpired:
        return [], 'node 跑超时了（某个调用可能死循环）'
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def looks_like_channel(s):
    """像通道名：`模块/方法`、`a:b`、`a.b`，或长度 ≥6 的驼峰/下划线名。

    排除三类噪音：
    1. 混淆 key（4 个随机字符，`0fuO`、`k817`）——太短；
    2. parseInt 校验值（`1359323lhJrXT`）——数字开头；
    3. 库内部标识符（`getOwnPropertyNames`、`prototype`）——没有分隔符且是常见 API。
    """
    if not s or len(s) < 3 or len(s) > 120:
        return False
    if any(ch in s for ch in ' \t\n(){}[]<>|&"\''):
        return False
    if s[0].isdigit():
        return False
    if '/' in s or ':' in s or '.' in s:
        return True
    if len(s) >= 6 and s.isalnum():
        return True
    return False


def deobfuscate_text(src, decode_fn_name='__DEC__'):
    """对一段混淆源码做字符串还原，返回 (strings, channels, 错误)。"""
    array_fn, array_body = find_array_function(src)
    if not array_fn:
        return [], [], '没找到 obfuscator.io 的字符串数组函数，这个文件可能不是这种混淆'
    decode_fn, decode_body = find_decode_function(src)
    calls = find_all_calls(src)
    if not calls:
        return [], [], '找到数组函数了，但没找到 (0x.., \'\\x..\') 形式的调用点'

    # 从调用点出发，把它们碰到的函数定义全捞出来（混淆里包装层数不定）
    names = sorted({c[0] for c in calls})
    bodies = collect_function_bodies(src, names)
    bodies[array_fn] = array_body      # 数组函数一定要在
    if decode_fn:
        bodies[decode_fn] = decode_body  # 解码函数也一定要在（调用点可能走别名）

    # 别名统一改回解码函数名：`ax(...)` → `d(...)`。
    # 这一步很关键：解码函数会自覆盖，别名在第一次调用后还指着「旧函数」，
    # 旧函数永远返回新函数而不是字符串，所以别名调不出东西。
    alias_map = {}
    if decode_fn:
        for m in re.finditer(r'([A-Za-z_$][\w$]*)\s*=\s*' + re.escape(decode_fn) + r'\b', src):
            alias_map[m.group(1)] = decode_fn

    def canonical(expr):
        for alias, real in alias_map.items():
            if expr.startswith(alias + '('):
                return real + expr[len(alias):]
        return expr

    lines = ['const calls = [']
    for _alias, expr in calls:
        lines.append('  () => ' + canonical(expr) + ',')
    lines.append('];')

    # 拼 Node 脚本：数组函数在前，其余函数按名字排（function 声明会提升，顺序不敏感），
    # 洗牌 IIFE 放在函数定义之后、调用之前。
    parts = [bodies[array_fn]] + [b for n, b in sorted(bodies.items()) if n != array_fn]
    shuffle = find_shuffle(src, array_fn)
    if shuffle:
        parts.append(shuffle)
    parts.append('\n'.join(lines))
    parts.append('const out = calls.map(f => { try { return f(); } '
                 'catch (e) { return null; } }).filter(v => typeof v === "string");')
    parts.append('console.log(JSON.stringify([...new Set(out)]));')
    strings, err = _run_node(parts)
    if err:
        return [], [], 'node 解码失败：' + err
    channels = sorted({s for s in strings if looks_like_channel(s)})
    return strings, channels, ''


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('target', help='混淆的 .js 文件，或 .asar（会扫里面每个 js）')
    ap.add_argument('--json', help='把结果写进这个 json')
    args = ap.parse_args()

    texts = []
    if args.target.lower().endswith('.asar'):
        import ipcsurface as t
        header, files = t.read_asar(args.target)
        try:
            for rel in sorted(files.keys()):
                if not rel.endswith('.js'):
                    continue
                blob = files[rel]
                if blob is None or b'_0x' not in blob[:200000]:
                    continue
                texts.append((rel, blob.decode('utf-8', 'ignore')))
        finally:
            files.close()
    else:
        with open(args.target, encoding='utf-8', errors='replace') as fh:
            texts.append((args.target, fh.read()))

    results = []
    for rel, src in texts:
        strings, channels, err = deobfuscate_text(src)
        if err:
            print(f'{rel}: {err}', file=sys.stderr)
            continue
        results.append({'file': rel, 'strings': strings, 'channels': channels})
        print(f'{rel}: 解出 {len(strings)} 个字符串，其中 {len(channels)} 个像通道名')
        for ch in channels[:40]:
            print('   ', ch)

    if args.json:
        with open(args.json, 'w', encoding='utf-8', newline='\n') as fh:
            json.dump(results, fh, ensure_ascii=False, indent=2)
        print(f'写进 {args.json}', file=sys.stderr)
    return 0 if results else 1


if __name__ == '__main__':
    raise SystemExit(main())
