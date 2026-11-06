#!/usr/bin/env python3
"""ipcsurface — 把一个 Electron 应用的能力面压成一页纸。

两种输入：

- 一个 .asar 包：自己解包，按字符串粗扫一遍。零依赖，不用装 REA，答案糙但快。
- 一份 REA 的 Evidence JSON：语法级分析，答案准，前提是先跑一遍 REA。

不管是哪种，输出都只摆证据、不下结论，并且先说自己能信多少。
"""

import argparse
import json
import os
import re
import struct
import sys
from collections import defaultdict

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


def scan_asar(files):
    """按字符串扫一遍源码。粗，但不用装任何东西。"""
    exposes, handlers, invokes = [], [], []
    dynamic, prefs, preloads = [], {}, []
    scanned = 0

    for rel, blob in files.items():
        if not rel.endswith(TEXT_EXT):
            continue
        try:
            text = blob.decode('utf-8')
        except UnicodeDecodeError:
            text = blob.decode('latin-1', 'ignore')
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
    }


def render_asar(target, facts, file_count, total_bytes):
    out = ['# Electron 能力面清单（粗扫）', '']
    out.append(f'- 目标：`{target}`')
    out.append(f'- {file_count} 个文件，{total_bytes / 1024 / 1024:.1f} MB，扫了 {facts["scanned"]} 个源码文件')
    out.append('')
    out.append('## 这份报告能信多少')
    out.append('')
    out.append('这是字符串级粗扫：只认写死在源码里的名字，不建语法树，跟着代码走不通。')
    out.append('要准的，先跑 `rea analyze-javascript-application`，再把 Evidence 喂给本工具。')
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
    for name, where in facts['handlers']:
        host[name].append(where)
    for name, where in facts['invokes']:
        page[name].append(where)
    for name in names:
        h = ', '.join(f'`{w}`' for w in host.get(name) or ['—'])
        p = ', '.join(f'`{w}`' for w in page.get(name) or ['—'])
        out.append(f'| `{name}` | {h} | {p} |')
    if not names:
        out.append('| — | — | — |')
    out.append('')

    out.append('## 没看清的地方')
    out.append('')
    out.append('这张表只能证明哪些看清了，不能证明没有什么。')
    out.append('')
    if facts['dynamic']:
        for what, where in facts['dynamic'][:20]:
            out.append(f'- 名字是算出来的不是写死的：`{what}`  `{where}`')
    else:
        out.append('- 没扫到算出来的通道名；但不等于没有，字符串拼法有无数种')
    out.append('- 混淆过、压过的代码，这里一条都认不出来')
    out.append('- 内存层面不看，越界、泄漏要在运行时或者 native 那边查')
    out.append('')
    out.append('> 粗扫只用来决定要不要认真查，不用来签字。')
    return '\n'.join(out)


# ---------------------------------------------------------------- evidence

def load_record(path):
    with open(path, encoding='utf-8-sig') as fh:
        data = json.load(fh)
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


def render_evidence(facts, findings):
    stats = facts['stats']
    out = ['# Electron 能力面清单', '']
    out.append(f"- 目标：`{facts['subject']}`")
    out.append(f"- 摘要 sha256：`{facts['sha'][:16]}…`")
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
    for channel in facts['channels']:
        page = ', '.join(f'`{w}`' for w in sorted(facts['invokes'].get(channel) or ['—']))
        host = ', '.join(f'`{w}`' for w in sorted(facts['handles'].get(channel) or ['—']))
        paired = '是' if channel in facts['invokes'] and channel in facts['handles'] else '缺一半'
        out.append(f'| `{channel}` | {page} | {host} | {paired} |')
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
    if findings:
        order = {'high': 0, 'medium': 1, 'info': 2}
        for level, text, where in sorted(findings, key=lambda f: order.get(f[0], 9)):
            out.append(f'- [{level}] {text}  `{where}`')
    else:
        out.append('- 没撞上规则')
    out.append('')
    out.append('> 依据静态语法，没有执行目标。「没写」不等于「没有」，也可能在别处设置。')
    return '\n'.join(out)


# ---------------------------------------------------------------- diff

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


# ---------------------------------------------------------------- cli

def looks_like_asar(path):
    return path.lower().endswith('.asar')


def analyse_asar(path):
    header, files = read_asar(path)
    facts = scan_asar(files)
    total = sum(len(v) for v in files.values())
    return facts, len(files), total


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='ipcsurface',
        description='把一个 Electron 应用的能力面压成一页纸。输入可以是 .asar，也可以是 REA 的 Evidence JSON')
    parser.add_argument('input', help='.asar 包，或 REA 的 Evidence JSON')
    parser.add_argument('-o', '--out', help='写到文件，不给就打到标准输出')
    parser.add_argument('--format', choices=('md', 'json'), default='md')
    parser.add_argument('--fail-on', choices=('high', 'medium'), help='出现该级别问题时以退出码 2 结束')
    parser.add_argument('--diff', metavar='OTHER', help='把 input 当成旧版，和另一份 Evidence 比')
    args = parser.parse_args(argv)

    if args.diff:
        old = collect_evidence(load_record(args.input))
        new = collect_evidence(load_record(args.diff))
        text = render_diff(old, new, os.path.basename(args.input), os.path.basename(args.diff))
        findings = []
    elif looks_like_asar(args.input):
        facts, count, total = analyse_asar(args.input)
        text = render_asar(args.input, facts, count, total)
        findings = []
    else:
        facts = collect_evidence(load_record(args.input))
        findings = audit_evidence(facts)
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
            text = render_evidence(facts, findings)

    if args.out:
        with open(args.out, 'w', encoding='utf-8') as fh:
            fh.write(text)
        print(f'wrote {args.out}', file=sys.stderr)
    else:
        print(text)

    if args.fail_on and findings:
        order = {'high': 0, 'medium': 1, 'info': 2}
        if any(order.get(level, 9) <= order[args.fail_on] for level, _, _ in findings):
            return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
