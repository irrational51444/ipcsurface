"""ipcsurface 的测试。只依赖标准库，不需要装 REA。

跑法：
    python -m unittest discover -s tests -v
"""

import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ipcsurface as ipc  # noqa: E402


def make_asar(files):
    """按 asar 的头格式手搓一个包，用来验证自己写的解析器。

    布局： [4][payload 长][4][json 长][json][文件内容...]
    """
    entries = {}
    blobs = b''
    for name, content in files.items():
        entries[name] = {'size': len(content), 'offset': str(len(blobs))}
        blobs += content
    header = {'files': entries}
    json_bytes = json.dumps(header).encode('utf-8')
    inner = struct.pack('<I', len(json_bytes)) + json_bytes
    payload = struct.pack('<I', len(inner)) + inner
    head = struct.pack('<I', 4) + struct.pack('<I', len(payload))
    return head + payload + blobs


class AsarTests(unittest.TestCase):
    def test_roundtrip(self):
        source = 'require("electron").ipcMain.handle("x:y", () => 1)'
        blob = make_asar({'src/main.js': source.encode('utf-8')})
        with tempfile.NamedTemporaryFile(suffix='.asar', delete=False) as fh:
            fh.write(blob)
            path = fh.name
        try:
            header, files = ipc.read_asar(path)
        finally:
            os.unlink(path)
        self.assertIn('src/main.js', files)
        self.assertEqual(files['src/main.js'].decode('utf-8'), source)
        self.assertIn('files', header)

    def test_rejects_garbage(self):
        with tempfile.NamedTemporaryFile(suffix='.asar', delete=False) as fh:
            fh.write(b'not an asar at all')
            path = fh.name
        try:
            with self.assertRaises(SystemExit):
                ipc.read_asar(path)
        finally:
            os.unlink(path)


class ScanTests(unittest.TestCase):
    def scan(self, source, name='src/main.js'):
        return ipc.scan_asar({name: source.encode('utf-8')})

    def test_literal_channel(self):
        facts = self.scan("ipcMain.handle('ledger:add', () => {})")
        self.assertEqual([n for n, _ in facts['handlers']], ['ledger:add'])
        self.assertEqual(facts['dynamic'], [])

    def test_concatenated_channel_is_dynamic(self):
        facts = self.scan("ipcMain.handle('ledger:' + 'shadow', () => {})")
        self.assertEqual(facts['handlers'], [])
        self.assertTrue(any('ledger:' in what for what, _ in facts['dynamic']))

    def test_computed_channel_is_dynamic(self):
        facts = self.scan("ipcMain.handle(makeChannel(op), () => {})")
        self.assertEqual(facts['handlers'], [])
        self.assertTrue(any('makeChannel' in what for what, _ in facts['dynamic']))

    def test_bridge_name(self):
        facts = self.scan("contextBridge.exposeInMainWorld('ledger', {})", 'src/preload.js')
        self.assertEqual([n for n, _ in facts['exposes']], ['ledger'])

    def test_web_preferences(self):
        facts = self.scan(
            'new BrowserWindow({webPreferences: {contextIsolation: true, nodeIntegration: false}})')
        self.assertEqual(facts['prefs']['contextIsolation'][0], 'true')
        self.assertEqual(facts['prefs']['nodeIntegration'][0], 'false')

    def test_non_electron_files_are_skipped(self):
        facts = self.scan('const a = 1;', 'src/util.js')
        self.assertEqual(facts['scanned'], 0)


def minimal_evidence(channels, dynamic=(), sender_checks=0, native=0):
    """手搓一份最小 Evidence，只放 collect_evidence 认的字段。"""
    edges = []
    nodes = []
    for channel in channels:
        edges.append({
            'relation': 'handles',
            'properties': {'channel': channel, 'resolution': 'literal'},
            'evidence': {'location': {'value': {'kind': 'source-range', 'source': 'src/main.js',
                                                'start': {'line': 9, 'column': 0}}}},
        })
        edges.append({
            'relation': 'invokes',
            'properties': {'channel': channel, 'resolution': 'literal'},
            'evidence': {'location': {'value': {'kind': 'source-range', 'source': 'src/preload.js',
                                                'start': {'line': 2, 'column': 0}}}},
        })
    for expr in dynamic:
        edges.append({
            'relation': 'handles',
            'properties': {'channel': None, 'channel_expression': expr, 'resolution': 'dynamic'},
            'evidence': {'location': {'value': {'kind': 'source-range', 'source': 'src/main.js',
                                                'start': {'line': 20, 'column': 0}}}},
        })
    nodes.append({
        'kind': 'browser-window',
        'observations': [{
            'properties': {'preload_path': 'preload.js',
                           'web_preferences': [
                               {'name': 'contextIsolation', 'value': {'status': 'literal', 'value': True}},
                               {'name': 'nodeIntegration', 'value': {'status': 'literal', 'value': False}},
                           ]},
            'evidence': {'location': {'value': {'kind': 'source-range', 'source': 'src/main.js',
                                                'start': {'line': 3, 'column': 0}}}},
        }],
    })
    return {
        'input_path': 'demo.asar',
        'root_artifact_sha256': 'a' * 64,
        'statistics': {'parsed_javascript_files': 2, 'visited_ast_nodes': 10, 'parse_failures': 0},
        'graph': {'nodes': nodes, 'edges': edges},
        'summary': {
            'ipc': {'dynamic_channel_operations': len(dynamic)},
            'sender_validation_observations': sender_checks,
            'native_addon_bindings': native,
        },
        'semantic_graph': {'coverage': {'families': [
            {'family': 'call-flow', 'status': 'partial', 'unknown_ids': ['u1', 'u2'],
             'retained_relations': 3},
        ]}},
    }


class EvidenceTests(unittest.TestCase):
    def test_collect(self):
        facts = ipc.collect_evidence(minimal_evidence(['a:1', 'a:2']))
        self.assertEqual(facts['channels'], ['a:1', 'a:2'])
        self.assertEqual(facts['dyn_channels'], [])

    def test_dynamic_channel_reported(self):
        facts = ipc.collect_evidence(minimal_evidence(['a:1'], dynamic=['makeChannel(op)']))
        self.assertEqual(facts['channels'], ['a:1'])
        self.assertEqual([e for e, _ in facts['dyn_channels']], ['makeChannel(op)'])

    def test_missing_sender_check_is_high(self):
        facts = ipc.collect_evidence(minimal_evidence(['a:1'], sender_checks=0))
        levels = [level for level, _, _ in ipc.audit_evidence(facts)]
        self.assertIn('high', levels)

    def test_sender_check_present_clears_it(self):
        facts = ipc.collect_evidence(minimal_evidence(['a:1'], sender_checks=2))
        texts = [text for _, text, _ in ipc.audit_evidence(facts)]
        self.assertFalse(any('sender' in t and '校验都没有' in t for t in texts))

    def test_report_puts_blind_spots_first(self):
        facts = ipc.collect_evidence(minimal_evidence(['a:1'], dynamic=['x()']))
        report = ipc.render_evidence(facts, ipc.audit_evidence(facts))
        self.assertLess(report.index('这份报告能信多少'), report.index('## 通道表'))
        self.assertIn('x()', report)

    def test_native_addon_note(self):
        facts = ipc.collect_evidence(minimal_evidence(['a:1'], native=2))
        report = ipc.render_evidence(facts, [])
        self.assertIn('2 个 native 模块', report)


class ObfuscationTests(unittest.TestCase):
    def test_eval_is_flagged(self):
        facts = ipc.scan_asar({'a.js': b'eval(decode(x))'})
        names = [h[0] for h in facts['obfuscation']]
        self.assertIn('eval 直接执行字符串', names)

    def test_base64_and_hex_names(self):
        source = "var _0x4a2f = 1; atob('abc')"
        facts = ipc.scan_asar({'a.js': source.encode('utf-8')})
        names = [h[0] for h in facts['obfuscation']]
        self.assertIn('base64 现场解码', names)
        self.assertIn('十六进制标识符', names)

    def test_clean_code_is_not_flagged(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('a:b', () => {})"})
        self.assertEqual(facts['obfuscation'], [])

    def test_weak_hit_does_not_claim_tampering(self):
        # new Function 是库的常规写法，不该被说成动过手脚
        facts = ipc.scan_asar({'a.js': b'var f = new Function("return 1")'})
        report = ipc.render_asar('demo.asar', facts, 1, 100)
        self.assertNotIn('这包动过手脚', report)
        self.assertIn('[弱]', report)

    def test_report_warns_when_obfuscated(self):
        facts = ipc.scan_asar({'a.js': b'eval(x)'})
        report = ipc.render_asar('demo.asar', facts, 1, 100)
        self.assertIn('这包动过手脚', report)
        self.assertIn('## 混淆痕迹', report)


class PeTests(unittest.TestCase):
    def test_rejects_non_pe(self):
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as fh:
            fh.write(b'MZ' + b'\0' * 200)
            path = fh.name
        try:
            with self.assertRaises(SystemExit):
                ipc.read_pe_imports(path)
        finally:
            os.unlink(path)

    def test_report_flags_dangerous_import(self):
        facts = {'machine': 0x8664, 'is_64': True, 'sections': 4,
                 'libraries': {'msvcrt.dll': ['strcpy', 'printf'], 'k.dll': ['memcpy']}}
        report = ipc.render_pe('demo.dll', facts, 1024)
        self.assertIn('strcpy', report.split('## 值得看一眼的')[1])
        self.assertIn('memcpy', report.split('## 值得看一眼的')[1])
        self.assertNotIn('printf —', report)

    def test_report_without_flags_says_so(self):
        facts = {'machine': 0x8664, 'is_64': True, 'sections': 3,
                 'libraries': {'a.dll': ['printf']}}
        self.assertIn('没撞上下面的表', ipc.render_pe('x.dll', facts, 10))


class RuntimeTests(unittest.TestCase):
    def test_missing_channel_is_marked(self):
        probe = {'handlers': ['a:1', 'b:2'],
                 'windows': [{'contextIsolation': True, 'nodeIntegration': False,
                              'sandbox': True, 'preload': 'p.js'}]}
        text = '\n'.join(ipc.render_runtime(probe, {'a:1'}))
        self.assertIn('`b:2`', text)
        self.assertIn('静态那边没看见', text)

    def test_probe_error_is_reported(self):
        text = '\n'.join(ipc.render_runtime({'error': '调试口没开'}))
        self.assertIn('调试口没开', text)

    def test_sandbox_shows_up(self):
        probe = {'handlers': [], 'windows': [{'contextIsolation': True,
                                              'nodeIntegration': False, 'sandbox': True}]}
        self.assertIn('sandbox=True', '\n'.join(ipc.render_runtime(probe, set())))


class AsarAuditTests(unittest.TestCase):
    def test_strong_obfuscation_counts_as_high(self):
        facts = ipc.scan_asar({'a.js': b'eval(x)'})
        self.assertIn('high', [f[0] for f in ipc.audit_asar(facts)])

    def test_hidden_channel_name_counts_as_medium(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('app:__internal', () => {})"})
        self.assertIn('medium', [f[0] for f in ipc.audit_asar(facts)])

    def test_clean_package_has_nothing(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('app:save', () => {})"})
        self.assertEqual(ipc.audit_asar(facts), [])

    def test_nested_asar_is_noticed(self):
        facts = ipc.scan_asar({'inner.asar': b'\0' * 16})
        self.assertEqual(facts['nested_asar'], ['inner.asar'])


class PeAuditTests(unittest.TestCase):
    def test_thread_injection_pair_is_high(self):
        facts = {'libraries': {'k.dll': ['CreateRemoteThread', 'WriteProcessMemory']}}
        self.assertIn('high', [f[0] for f in ipc.audit_pe(facts)])

    def test_unsafe_string_func_is_medium(self):
        facts = {'libraries': {'m.dll': ['strcpy', 'printf']}}
        levels = [f[0] for f in ipc.audit_pe(facts)]
        self.assertIn('medium', levels)

    def test_harmless_imports_produce_nothing(self):
        self.assertEqual(ipc.audit_pe({'libraries': {'a.dll': ['printf', 'malloc']}}), [])


class BaselineTests(unittest.TestCase):
    def test_roundtrip(self):
        findings = [('high', '一条 sender 校验都没有', 'main 进程')]
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as fh:
            path = fh.name
        try:
            ipc.save_baseline(path, findings, ['a:1'])
            loaded = ipc.load_baseline(path)
        finally:
            os.unlink(path)
        self.assertEqual(loaded['findings'], findings)
        self.assertEqual(loaded['channels'], ['a:1'])

    def test_missing_baseline_is_empty(self):
        loaded = ipc.load_baseline(None)
        self.assertEqual(loaded['findings'], [])

    def test_report_says_what_was_suppressed(self):
        facts = ipc.collect_evidence(minimal_evidence(['a:1']))
        report = ipc.render_evidence(facts, [], known_count=4)
        self.assertIn('另有 4 条是基线里就有的', report)
        self.assertIn('没有新的', report)


class DiffTests(unittest.TestCase):
    def test_added_and_removed(self):
        old = ipc.collect_evidence(minimal_evidence(['a:1', 'a:2']))
        new = ipc.collect_evidence(minimal_evidence(['a:2', 'a:3']))
        report = ipc.render_diff(old, new, 'v1', 'v2')
        added = report.split('## 新加的')[1].split('## 没了的')[0]
        removed = report.split('## 没了的')[1]
        self.assertIn('a:3', added)
        self.assertIn('a:1', removed)

    def test_new_dynamic_channel_surfaces(self):
        old = ipc.collect_evidence(minimal_evidence(['a:1']))
        new = ipc.collect_evidence(minimal_evidence(['a:1'], dynamic=['makeChannel(op)']))
        report = ipc.render_diff(old, new, 'v1', 'v2')
        self.assertIn('makeChannel(op)', report)


if __name__ == '__main__':
    unittest.main()
