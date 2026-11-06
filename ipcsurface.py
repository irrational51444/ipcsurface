#!/usr/bin/env python3
"""ipcsurface — 把一个 Electron 应用的能力面压成一页纸。

两种输入：

- 一个 .asar 包：自己解包，按字符串粗扫一遍。零依赖，不用装 REA，答案糙但快。
- 一份 REA 的 Evidence JSON：语法级分析，答案准，前提是先跑一遍 REA。

不管是哪种，输出都只摆证据、不下结论，并且先说自己能信多少。
"""

import argparse
import datetime
import json
import os
import re
import struct
import sys
from collections import defaultdict

__version__ = '0.5.0'

HIGH_RISK_HINTS = ('__', 'internal', 'debug', 'admin')

# ---------------------------------------------------------------- asar

def read_asar(path):
    """解一个 asar，返回 (文件树, {相对路径: bytes})。

    asar 的头是个 pickle：8 字节前缀，其中后 4 字节是头部长度；
    头部本身又是 4 字节长度 + JSON。
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

        files = {}

        def walk(node, prefix):
            for name, child in (node.get('files') or {}).items():
                rel = f'{prefix}{name}'
                if 'files' in child:
                    walk(child, rel + '/')
                else:
                    offset = int(child.get('offset', 0))
                    size = int(child.get('size', 0))
                    fh.seek(base + offset)
                    files[rel] = fh.read(size)

        walk(header, '')
        return header, files


TEXT_EXT = ('.js', '.mjs', '.cjs', '.jsx', '.ts', '.json', '.html', '.asar')

PATTERNS = [
    ('expose', re.compile(r"exposeInMainWorld\(\s*['\"]([^'\"]+)['\"]")),
    ('handle', re.compile(r"ipcMain\.(?:handle|handleOnce|on)\(\s*['\"]([^'\"]+)['\"]")),
    ('invoke', re.compile(r"ipcRenderer\.(?:invoke|send|sendSync)\(\s*['\"]([^'\"]+)['\"]")),
    ('dynamic_handle', re.compile(r"ipcMain\.(?:handle|on)\(\s*([^'\"\s][^,)]*\)?)")),
    ('dynamic_invoke', re.compile(r"ipcRenderer\.(?:invoke|send)\(\s*([^'\"\s][^,)]*\)?)")),
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
    ('eval 直接执行字符串', re.compile(r'\beval\s*\('), 'strong'),
    ('十六进制标识符', re.compile(r'\b_0x[0-9a-fA-F]{2,}'), 'strong'),
    ('超长单行（压过）', re.compile(r'^.{2000,}$', re.M), 'strong'),
    ('base64 现场解码', re.compile(r'\batob\s*\('), 'weak'),
    ('Function 构造器拼代码', re.compile(r'\bnew\s+Function\s*\('), 'weak'),
    ('charCode 拼字符串', re.compile(r'fromCharCode'), 'weak'),
]


# 字符串字面量相加，先折成一段：'ledger:' + 'add' → 'ledger:add'
# 只折两头都是纯字面量的，别的一律不动。行数不变，行号还能对得上。
CONCAT_QUOTES = re.compile(r"""(['"])([^'"\\]*)\1\s*\+\s*(['"])([^'"\\]*)\3""")


def fold_literals(text):
    for _ in range(4):
        folded = CONCAT_QUOTES.sub(
            lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), text)
        if folded == text:
            break
        text = folded
    return text


def detect_obfuscation(text, rel):
    hits = []
    for name, pattern, level in OBF_PATTERNS:
        match = pattern.search(text)
        if match:
            hits.append((name, f'{rel}:{line_of(text, match.start())}', level))
    return hits


def scan_asar(files):
    """按字符串扫一遍源码。粗，但不用装任何东西。"""
    exposes, handlers, invokes = [], [], []
    dynamic, prefs, preloads = [], {}, []
    obfuscation = []
    scanned = 0

    for rel, blob in files.items():
        if not rel.endswith(TEXT_EXT):
            continue
        try:
            text = blob.decode('utf-8')
        except UnicodeDecodeError:
            text = blob.decode('latin-1', 'ignore')
        text = fold_literals(text)
        obfuscation.extend(detect_obfuscation(text, rel))
        if 'ipcMain' not in text and 'contextBridge' not in text and 'webPreferences' not in text:
            continue
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


def render_asar(target, facts, file_count, total_bytes, show_all=False, findings=None):
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


def load_probe(path):
    """读探针的输出。读不了就说清楚，别甩堆栈。"""
    try:
        with open(path, encoding='utf-8-sig') as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        raise SystemExit(f'运行时结果读不了：{path}\n'
                         '先用 probe/run.js 跑一遍，把它的输出存成文件:\n'
                         '  node probe/run.js 应用目录 6 > probe.json')
    if not isinstance(data, dict):
        raise SystemExit(f'运行时结果不是那个格式：{path}')
    return data


def load_poke(path):
    """敲击结果是一串记录，不是对象。读坏了还是那句话。"""
    try:
        with open(path, encoding='utf-8-sig') as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        raise SystemExit(f'敲击结果读不了：{path}\n'
                         '先用 probe/poke.js 跑一遍:\n'
                         '  node probe/poke.js 应用目录 6 > poke.json')
    return data


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

    by_channel = defaultdict(lambda: {'boom': [], 'ok': []})
    for row in rows:
        bucket = 'boom' if not row.get('ok') else 'ok'
        by_channel[row.get('channel', '?')][bucket].append(row.get('payload', '?'))

    swallow = [c for c, v in by_channel.items() if v['ok']]
    boom = [c for c, v in by_channel.items() if v['boom']]
    out.append(f'- 敲了 {len(by_channel)} 条通道，每条四五种不合规的输入')
    out.append('')

    if swallow:
        out.append('### 照收的（该看一眼有没有校验）')
        out.append('')
        for channel in swallow[:15]:
            kinds = '、'.join(dict.fromkeys(by_channel[channel]['ok']))
            out.append(f'- `{channel}`：喂 {kinds} 都照收，还返回了结果')
        if len(swallow) > 15:
            out.append(f'- 还有 {len(swallow) - 15} 条同样照收')
        out.append('')
        out.append('> 照收不等于有洞。但参数进来不看看就往下走，是这类通道最常见的问题。')
        out.append('')

    if boom:
        out.append('### 抛错的（可能人家本来就该拒）')
        out.append('')
        for channel in boom[:15]:
            kinds = '、'.join(dict.fromkeys(by_channel[channel]['boom']))
            out.append(f'- `{channel}`：喂 {kinds} 时抛错')
        out.append('')
        out.append('> 抛错不一定坏，也可能是拒绝得对。区别在于它拒绝之前有没有干活。')
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
    if facts['sender_checks'] == 0:
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


def load_baseline(path):
    """读上次留下的一份发现。没有就当空的。"""
    if not path:
        return {'findings': [], 'channels': []}
    try:
        with open(path, encoding='utf-8-sig') as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        raise SystemExit(f'基线读不了：{path}')
    return {
        'findings': [tuple(item) for item in data.get('findings') or []],
        'channels': list(data.get('channels') or []),
    }


def save_baseline(path, findings, channels):
    payload = {
        'findings': [list(item) for item in findings],
        'channels': list(channels),
    }
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print(f'基线写到 {path}', file=sys.stderr)


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


def analyse_asar(path):
    header, files = read_asar(path)
    facts = scan_asar(files)
    recovered = scan_sourcemaps(files)
    if recovered:
        extra = scan_asar(recovered)
        for key in ('exposes', 'handlers', 'invokes', 'dynamic', 'preloads', 'obfuscation'):
            merged = set(facts[key]) | set(extra[key])
            facts[key] = sorted(merged)
        facts['scanned'] += extra['scanned']
    facts['recovered'] = sorted(recovered)
    total = sum(len(v) for v in files.values())
    return facts, len(files), total


def main(argv=None):
    # Windows 控制台默认不是 UTF-8，直接打中文会乱码
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding='utf-8')
        except (AttributeError, ValueError):
            pass

    parser = argparse.ArgumentParser(
        prog='ipcsurface',
        description='把一个 Electron 应用的能力面压成一页纸。'
                    '输入可以是 .asar、REA 的 Evidence JSON，或者一个 dll/exe。',
        epilog='报告第一节永远是「这份报告能信多少」，然后是证据，最后是下一步。')
    parser.add_argument('input', help='.asar 包、REA 的 Evidence JSON，或 dll/exe')
    parser.add_argument('--version', action='version', version=f'ipcsurface {__version__}')
    parser.add_argument('-o', '--out', help='写到文件，不给就打到标准输出')
    parser.add_argument('--format', choices=('md', 'json'), default='md')
    parser.add_argument('--fail-on', choices=('high', 'medium'), help='出现该级别问题时以退出码 2 结束')
    parser.add_argument('--diff', metavar='OTHER', help='把 input 当成旧版，和另一份 Evidence 比')
    parser.add_argument('--all', action='store_true', help='不截断，把找到的全列出来')
    parser.add_argument('--baseline', metavar='FILE',
                        help='上次的发现，这次只报新冒出来的')
    parser.add_argument('--write-baseline', metavar='FILE',
                        help='把这次的发现存成基线，下次用 --baseline 读它')
    parser.add_argument('--runtime', metavar='PROBE_JSON',
                        help='probe/run.js 的输出，把跑起来看见的通道并进报告')
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
        facts, count, total = analyse_asar(args.input)
        findings = audit_asar(facts)
        names = {n for n, _ in facts['handlers']} | {n for n, _ in facts['invokes']}
        if args.format == 'json':
            text = json.dumps({
                'mode': 'asar',
                'subject': args.input,
                'files': count,
                'bytes': total,
                'channels': sorted(names),
                'dynamic': [what for what, _ in facts['dynamic']],
                'exposes': [n for n, _ in facts['exposes']],
                'web_preferences': {k: v[0] for k, v in facts['prefs'].items()},
                'native_files': facts['native_files'],
                'obfuscation': [{'what': n, 'where': w, 'level': l}
                                for n, w, l in facts['obfuscation']],
                'version': __version__,
            }, ensure_ascii=False, indent=2)
        else:
            text = render_asar(args.input, facts, count, total,
                               show_all=args.all, findings=findings)
        names = {n for n, _ in facts['handlers']} | {n for n, _ in facts['invokes']}
        summary_line = f'{len(names)} 条通道，{len(facts["dynamic"])} 处名字是算的'
        if args.runtime:
            text += '\n'.join(render_runtime(load_probe(args.runtime), names))
        if args.poke:
            text += '\n'.join(render_poke(load_poke(args.poke)))
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
        with open(args.out, 'w', encoding='utf-8') as fh:
            fh.write(text)
        # 一行就说完，人不用打开文件也知道要不要看
        print(f'wrote {args.out} — {summary_line}', file=sys.stderr)
    else:
        print(text)

    if args.fail_on and findings:
        order = {'high': 0, 'medium': 1, 'info': 2}
        if any(order.get(level, 9) <= order[args.fail_on] for level, _, _ in findings):
            return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
