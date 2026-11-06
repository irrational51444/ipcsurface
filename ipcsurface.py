#!/usr/bin/env python3
"""ipcsurface — 把 REA 的 Electron 证据包压成一页能力面清单。

输入是 `rea analyze-javascript-application` 产出的完整 Evidence JSON，
输出一张表：preload 暴露了什么、每条 IPC 通道两头落在哪一行、哪几条值得盯。

只读静态证据，不执行目标。
"""

import argparse
import json
import sys
from collections import defaultdict

HIGH_RISK_HINTS = ('__', 'internal', 'debug', 'admin', 'test', 'dev')


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
        start = value['start']
        return f"{value['source']}:{start['line'] + 1}"
    if value.get('kind') == 'artifact-path':
        return value.get('path', '?')
    return '?'


def collect(result):
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
                windows.append({
                    'where': where,
                    'preload': props.get('preload_path'),
                    'prefs': prefs,
                })
            else:
                bridges.append({
                    'key': props.get('api_key') or props.get('key'),
                    'world': props.get('world'),
                    'where': where,
                })

    invokes = defaultdict(set)
    handles = defaultdict(set)
    exports = defaultdict(set)
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

    channels = sorted(set(invokes) | set(handles))

    semantic = result.get('semantic_graph') or {}
    coverage = semantic.get('coverage') or {}
    families = []
    for fam in coverage.get('families') or []:
        unknown = len(fam.get('unknown_ids') or [])
        if fam.get('status') != 'complete' or unknown:
            families.append({
                'name': fam.get('family'),
                'status': fam.get('status'),
                'unknown': unknown,
                'retained': fam.get('retained_relations'),
            })
    families.sort(key=lambda f: (-f['unknown'], f['name'] or ''))

    dyn_channels = []
    for edge in graph['edges']:
        props = edge.get('properties') or {}
        if not props.get('channel'):
            continue
        if props.get('channel_expression') or props.get('resolution') in ('dynamic', 'unresolved', 'computed'):
            expr = props.get('channel_expression') or '?'
            dyn_channels.append((expr, loc(edge.get('evidence'))))
    dyn_channels = sorted(set(dyn_channels))

    return {
        'subject': result.get('input_path') or '?',
        'sha': result.get('root_artifact_sha256') or '?',
        'stats': result.get('statistics') or {},
        'windows': windows,
        'bridges': bridges,
        'invokes': invokes,
        'handles': handles,
        'exports': exports,
        'channels': channels,
        'families': families,
        'dyn_channels': dyn_channels,
        'ipc': summary.get('ipc') or {},
        'sender_checks': summary.get('sender_validation_observations'),
        'limitations': result.get('limitations') or [],
    }


def audit(facts):
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


def render_markdown(facts, findings):
    stats = facts['stats']
    out = ['# Electron 能力面清单', '']
    out.append(f"- 目标：`{facts['subject']}`")
    out.append(f"- 摘要 sha256：`{facts['sha'][:16]}…`")
    out.append(f"- 解析 {stats.get('parsed_javascript_files', '?')} 个 JS 文件，"
               f"{stats.get('visited_ast_nodes', '?')} 个 AST 节点，"
               f"失败 {stats.get('parse_failures', 0)} 个")
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
    if not facts['dyn_channels'] and facts['ipc'].get('dynamic_channel_operations'):
        out.append(f"- {facts['ipc']['dynamic_channel_operations']} 个通道操作是动态的，名字没定下来")
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


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='ipcsurface',
        description='把 REA 的 Electron 证据包压成一页能力面清单')
    parser.add_argument('evidence', help='REA analyze-javascript-application 产出的 Evidence JSON')
    parser.add_argument('-o', '--out', help='写到文件，不给就打到标准输出')
    parser.add_argument('--format', choices=('md', 'json'), default='md')
    parser.add_argument('--fail-on', choices=('high', 'medium'), help='出现该级别问题时以退出码 2 结束')
    args = parser.parse_args(argv)

    facts = collect(load_record(args.evidence))
    findings = audit(facts)

    if args.format == 'json':
        payload = {
            'subject': facts['subject'],
            'channels': facts['channels'],
            'paired': [c for c in facts['channels'] if c in facts['invokes'] and c in facts['handles']],
            'bridges': facts['bridges'],
            'windows': facts['windows'],
            'findings': [{'level': l, 'text': t, 'location': w} for l, t, w in findings],
        }
        text = json.dumps(payload, ensure_ascii=False, indent=2)
    else:
        text = render_markdown(facts, findings)

    if args.out:
        with open(args.out, 'w', encoding='utf-8') as fh:
            fh.write(text)
        print(f'wrote {args.out}', file=sys.stderr)
    else:
        print(text)

    if args.fail_on:
        order = {'high': 0, 'medium': 1, 'info': 2}
        threshold = order[args.fail_on]
        if any(order.get(level, 9) <= threshold for level, _, _ in findings):
            return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
