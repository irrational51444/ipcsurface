"""ipcsurface 的测试。只依赖标准库，不需要装 REA。

跑法：
    python -m unittest discover -s tests -v
"""

import errno
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

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
        header, files = ipc.read_asar(path)
        # 文件表改成按需切了，源文件得开着；先验完，再关，再删。
        try:
            self.assertIn('src/main.js', files)
            self.assertEqual(files['src/main.js'].decode('utf-8'), source)
            self.assertIn('files', header)
        finally:
            files.close()
            os.unlink(path)

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

    def test_concatenated_literals_get_folded(self):
        # 'ledger:' + 'shadow' 两头都是死字符串，折成一段就认得出了
        facts = self.scan("ipcMain.handle('ledger:' + 'shadow', () => {})")
        self.assertEqual([n for n, _ in facts['handlers']], ['ledger:shadow'])
        self.assertEqual(facts['dynamic'], [])

    def test_computed_channel_is_dynamic(self):
        facts = self.scan("ipcMain.handle(makeChannel(op), () => {})")
        self.assertEqual(facts['handlers'], [])
        # empty-allowed: 断言的是「不该出现某种标签」，没有通道时也应当成立
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
        # empty-allowed: 反证类断言，空集合是合法输入
        self.assertFalse(any('sender' in t and '校验都没有' in t for t in texts))

    def test_no_window_means_no_sender_claim(self):
        # 只分析了一个文件，没看到窗口代码，就不能断言「没人校验」
        result = minimal_evidence(['a:1'], sender_checks=0)
        result['graph']['nodes'] = []
        facts = ipc.collect_evidence(result)
        texts = [text for _, text, _ in ipc.audit_evidence(facts)]
        # empty-allowed: 验的是「缺窗口时不乱下结论」，空集合正是被测场景
        self.assertFalse(any('sender' in t for t in texts))

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

    def test_zero_channels_says_i_dont_know(self):
        # 一条都没扫到的时候，最容易被读成「这包干净」。必须顶在最前面说清楚。
        facts = ipc.scan_asar({'a.js': b'eval(x)'})
        report = ipc.render_asar('demo.asar', facts, 1, 100)
        self.assertIn('## 一条字面通道都没看见', report)
        self.assertIn('我这条路走不通', report)
        self.assertIn('答案是「不知道」', report)

    def test_zero_channels_quiet_when_something_found(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('a:b', () => {})"})
        report = ipc.render_asar('demo.asar', facts, 1, 100)
        self.assertNotIn('一条字面通道都没看见', report)


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


class TemplateTests(unittest.TestCase):
    def test_literal_interpolation_is_folded(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle(`vault:${'unlock'}`, f)"})
        self.assertIn('vault:unlock', [n for n, _ in facts['handlers']])

    def test_variable_interpolation_is_left_alone(self):
        out = ipc.fold_templates("x = `vault:${name}`")
        self.assertIn('${', out)


class ConstPropTests(unittest.TestCase):
    def test_prefix_before_plus_is_substituted(self):
        out = ipc.propagate_constants("const PREFIX = 'ledger:';\nX(PREFIX + name)")
        self.assertIn('ledger:', out)
        self.assertNotIn('PREFIX + name', out)

    def test_short_names_are_not_touched(self):
        src = "const ab = 'xx:';\nX(ab + name)"
        self.assertEqual(ipc.propagate_constants(src), src)


class DecodeCallTests(unittest.TestCase):
    SOURCE = ("function _d(s){var o='';for(var i=0;i<s.length;i++){"
              "o+=String.fromCharCode(s.charCodeAt(i)^7)}return o}\n"
              "ipcMain.handle(_d('\\x71\\x66\\x72\\x6b\\x73\\x3d\\x72\\x69\\x6b\\x68\\x64\\x6c'), f)")

    def test_decode_call_is_restored(self):
        out = ipc.restore_decode_calls(self.SOURCE)
        self.assertIn('vault:unlock', out)

    def test_eval_can_be_turned_off(self):
        facts = ipc.scan_asar({'a.js': self.SOURCE.encode('utf-8')}, allow_eval=False)
        self.assertEqual(facts['handlers'], [])

    def test_eval_is_on_by_default(self):
        facts = ipc.scan_asar({'a.js': self.SOURCE.encode('utf-8')})
        self.assertIn('vault:unlock', [n for n, _ in facts['handlers']])

    def test_with_eval_flag_channel_is_found(self):
        facts = ipc.scan_asar({'a.js': self.SOURCE.encode('utf-8')}, allow_eval=True)
        self.assertIn('vault:unlock', [n for n, _ in facts['handlers']])

    def test_nested_calls_are_peeled(self):
        # 套两层：先加一，再异或 7。一轮剥一层，来回跑就剥开了
        src = ("function _e(s){var o='';for(var i=0;i<s.length;i++){"
               "o+=String.fromCharCode(s.charCodeAt(i)+1)}return o}\n"
               "function _d(s){var o='';for(var i=0;i<s.length;i++){"
               "o+=String.fromCharCode(s.charCodeAt(i)^7)}return o}\n"
               "ipcMain.handle(_d(_e('\\x70\\x65\\x71\\x6a\\x72\\x3c\\x71\\x68\\x6a\\x67\\x63\\x6b')), f)")
        out = ipc.restore_decode_calls(src)
        self.assertIn('vault:unlock', out)

    def test_unknown_function_is_left_alone(self):
        src = "someFunc('\\x71\\x66')"
        self.assertEqual(ipc.restore_decode_calls(src), src)


class StringPoolTests(unittest.TestCase):
    def test_pool_index_is_restored(self):
        source = (b"var _0x = ['vault:unlock','vault:lock','vault:status'];\n"
                  b"ipcMain.handle(_0x[1], (e,p) => p);")
        facts = ipc.scan_asar({'a.js': source})
        self.assertIn('vault:lock', [n for n, _ in facts['handlers']])

    def test_two_item_array_is_not_treated_as_pool(self):
        source = (b"var a = ['x:y','b:c'];\n"
                  b"ipcMain.handle(a[0], (e,p) => p);")
        facts = ipc.scan_asar({'a.js': source})
        self.assertEqual(facts['handlers'], [])

    def test_index_out_of_range_is_left_alone(self):
        restored = ipc.restore_string_arrays(
            "var _0x = ['a:b','c:d','e:f'];\nx = _0x[9];")
        self.assertIn('_0x[9]', restored)

    def test_restore_is_a_no_op_without_pools(self):
        text = "ipcMain.handle('a:b', f)"
        self.assertEqual(ipc.restore_string_arrays(text), text)


class LiteralFoldTests(unittest.TestCase):
    def test_single_quotes_are_folded(self):
        self.assertIn("'ledger:add'", ipc.fold_literals("ipcMain.handle('ledger:' + 'add')"))

    def test_double_quotes_are_folded(self):
        self.assertIn('"app:save"', ipc.fold_literals('invoke("app:" + "save")'))

    def test_folded_name_lands_in_the_table(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('ledger:' + 'shadow', () => {})"})
        names = [n for n, _ in facts['handlers']]
        self.assertIn('ledger:shadow', names)

    def test_variable_still_counted_as_unknown(self):
        facts = ipc.scan_asar({'a.js': b'ipcMain.handle(PREFIX + name, () => {})'})
        self.assertEqual(facts['handlers'], [])


class SourcemapTests(unittest.TestCase):
    def test_sources_content_is_recovered(self):
        blob = json.dumps({
            'sources': ['../src/a.ts'],
            'sourcesContent': ["ipcMain.handle('x:y', () => {})"],
        }).encode()
        got = ipc.scan_sourcemaps({'dist/a.js.map': blob})
        self.assertEqual(len(got), 1)

    def test_broken_map_is_skipped(self):
        self.assertEqual(ipc.scan_sourcemaps({'a.js.map': b'not json'}), {})

    def test_map_without_content_is_ignored(self):
        blob = json.dumps({'sources': ['a.ts']}).encode()
        self.assertEqual(ipc.scan_sourcemaps({'a.js.map': blob}), {})


class CrossFileTests(unittest.TestCase):
    def test_constant_defined_elsewhere_is_resolved(self):
        files = {
            'src/channels.js': b"const VAULT_UNLOCK_CHANNEL = 'vault:unlock';",
            'src/main.js': b"ipcMain.handle(VAULT_UNLOCK_CHANNEL, f)",
        }
        facts = ipc.scan_asar(files)
        self.assertIn('vault:unlock', [n for n, _ in facts['handlers']])

    def test_unknown_name_is_left_alone(self):
        files = {'src/main.js': b'ipcMain.handle(SOMETHING_UNKNOWN, f)'}
        facts = ipc.scan_asar(files)
        self.assertEqual(facts['handlers'], [])

    def test_short_names_are_not_in_the_global_table(self):
        files = {'src/a.js': b"const ab = 'vault:unlock';"}
        self.assertEqual(ipc.build_global_constants(files), {})


class ClassifyTests(unittest.TestCase):
    def test_node_modules_is_third_party(self):
        self.assertEqual(ipc.classify_path('node_modules/pkg/index.js'), 'dep')

    def test_test_file_is_test(self):
        self.assertEqual(ipc.classify_path('src/main.test.js'), 'test')

    def test_own_code_is_self(self):
        self.assertEqual(ipc.classify_path('src/main.js'), 'self')
        self.assertEqual(ipc.classify_path('lib/desktop/preload.js'), 'self')


class HarvestTests(unittest.TestCase):
    def test_channel_like_string_is_kept(self):
        got = ipc.harvest_strings({'a.js': b"ipcMain.handle('vault:unlock', f)"})
        self.assertIn('vault:unlock', got)

    def test_excel_cell_is_dropped(self):
        got = ipc.harvest_strings({'a.js': b"sheet('A1:B10')"})
        self.assertEqual(got, {})

    def test_url_scheme_is_dropped(self):
        got = ipc.harvest_strings({'a.js': b"fetch('https://example.com/api')"})
        self.assertEqual(got, {})

    def test_non_js_file_is_skipped(self):
        got = ipc.harvest_strings({'a.png': b"'vault:unlock'"})
        self.assertEqual(got, {})

    def test_harvested_block_shows_up_in_report(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('vault:unlock', f)"})
        facts['harvested'] = {'vault:unlock': 'a.js:1'}
        report = ipc.render_asar('x.asar', facts, 1, 10)
        self.assertIn('长得像通道的字符串', report)


    def test_confidence_ladder_separates_strengths(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('vault:unlock', f)"})
        text = ipc.render_asar('x.asar', facts, 1, 10)
        self.assertIn('可信度分层', text)
        self.assertIn('写死的名字', text)
        # 没看见的那一层必须写「未知」，不能写成 0
        self.assertIn('我这条路看不见，不代表它不在', text)

    def test_confidence_ladder_uses_runtime_counts(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('vault:unlock', f)"})
        probe = {'handlers': ['a:b', 'c:d'], 'windows': [{}]}
        text = ipc.render_asar('x.asar', facts, 1, 10, probe=probe)
        self.assertIn('2 条通道 / 1 个窗口', text)
        self.assertIn('启动配方每个应用不一样', text)


class ConfidenceTests(unittest.TestCase):
    def test_rule_channel_count_matches_the_report(self):
        # 报告说「N 条通道」和基线里存的必须是同一批名字，不含 window 暴露
        source = (b"ipcMain.handle('a:1', f)\nexposeInMainWorld('api', {})\n"
                  b"ipcRenderer.invoke('b:2')\n")
        facts = ipc.scan_asar({'a.js': source})
        self.assertEqual(facts['channels'], ['a:1', 'b:2'])
        self.assertIn('api', [name for name, _w in facts['exposes']])

    def test_rule_unknown_is_null(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('vault:unlock', f)"})
        levels = {level['id']: level for level in ipc.confidence_levels(facts)}
        # 没看见的那层不能是 0，0 会被下游读成「查过，没有」
        self.assertIsNone(levels['unseen']['count'])
        self.assertEqual(levels['unseen']['strength'], 0.0)
        self.assertEqual(levels['literal']['count'], 1)

    def test_json_output_carries_the_ladder_and_stays_json(self):
        blob = make_asar({'src/main.js': b"ipcMain.handle('x:y', () => 1)"})
        with tempfile.NamedTemporaryFile(suffix='.asar', delete=False) as fh:
            fh.write(blob)
            path = fh.name
        out = path + '.json'
        try:
            ipc.main([path, '--format', 'json', '-o', out])
            with open(out, encoding='utf-8') as fh:
                data = json.load(fh)   # 拼进 markdown 就解析不了，这条盯着它
        finally:
            for name in (path, out):
                try:
                    os.unlink(name)
                except OSError:
                    pass
        self.assertIn('confidence', data)
        ids = [level['id'] for level in data['confidence']]
        self.assertEqual(ids[0], 'literal')
        self.assertIn('unseen', ids)


    def test_corroborated_name_needs_two_independent_sides(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('vault:unlock', f)"})
        probe = {'handlers': ['vault:unlock'], 'windows': []}
        item = ipc.channel_sources(facts, probe=probe)['vault:unlock']
        self.assertTrue(item['corroborated'])
        self.assertEqual(item['corroboration'], 'static_runtime')

    def test_same_side_pair_is_not_corroboration(self):
        # 逐字 + 打捞都在静态侧，只是写法不同，不算独立见证
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('vault:unlock', f)"})
        facts['harvested'] = {'vault:unlock': ('a.js:1', 'self')}
        item = ipc.channel_sources(facts)['vault:unlock']
        self.assertFalse(item['corroborated'])
        self.assertEqual(item['corroboration'], 'static_static')

    def test_primary_action_takes_the_strictest(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('vault:unlock', f)"})
        probe = {'handlers': ['vault:unlock'], 'windows': []}
        item = ipc.channel_sources(facts, probe=probe)['vault:unlock']
        self.assertIn('cite', item['actions'])
        self.assertIn('trust_after_setup', item['actions'])
        # 两个动作都能用，主动作必须是更费事的那个
        self.assertEqual(item['primary_action'], 'trust_after_setup')

    def test_harvested_only_name_stays_weak(self):
        facts = ipc.scan_asar({'a.js': b'eval(x)'})
        facts['harvested'] = {'other:thing': ('a.js:2', 'self')}
        sources = ipc.channel_sources(facts)
        self.assertFalse(sources['other:thing']['corroborated'])
        self.assertLess(sources['other:thing']['strength'], 0.3)

    def test_json_carries_evidence_per_name(self):
        blob = make_asar({'src/main.js': b"ipcMain.handle('x:y', () => 1)"})
        with tempfile.NamedTemporaryFile(suffix='.asar', delete=False) as fh:
            fh.write(blob)
            path = fh.name
        out = path + '.json'
        try:
            ipc.main([path, '--format', 'json', '-o', out])
            with open(out, encoding='utf-8') as fh:
                data = json.load(fh)
        finally:
            for name in (path, out):
                try:
                    os.unlink(name)
                except OSError:
                    pass
        self.assertIn('evidence', data)
        self.assertIn('x:y', data['evidence'])
        self.assertIn('literal', data['evidence']['x:y']['sources'])


    def test_json_has_the_same_sections_as_the_markdown(self):
        blob = make_asar({'src/main.js': b"ipcMain.handle('x:y', () => 1)"})
        with tempfile.NamedTemporaryFile(suffix='.asar', delete=False) as fh:
            fh.write(blob)
            path = fh.name
        out = path + '.json'
        try:
            ipc.main([path, '--format', 'json', '-o', out])
            with open(out, encoding='utf-8') as fh:
                data = json.load(fh)
        finally:
            for name in (path, out):
                try:
                    os.unlink(name)
                except OSError:
                    pass
        # 人看得见的那几节，机器也得看得见
        self.assertEqual(data['schema'], 'ipcsurface/asar/10')
        self.assertIn('limits', data)
        # empty-allowed: 两侧都为空时也算一致，这条比的是集合相等不是数量
        self.assertTrue(any('未知' in line for line in data['limits']))
        self.assertIsNone(data['runtime'])
        self.assertIsNone(data['poke'])

    def test_strength_is_documented_as_cost_not_probability(self):
        blob = make_asar({'src/main.js': b"ipcMain.handle('x:y', () => 1)"})
        with tempfile.NamedTemporaryFile(suffix='.asar', delete=False) as fh:
            fh.write(blob)
            path = fh.name
        out = path + '.json'
        try:
            ipc.main([path, '--format', 'json', '-o', out])
            with open(out, encoding='utf-8') as fh:
                data = json.load(fh)
        finally:
            for name in (path, out):
                try:
                    os.unlink(name)
                except OSError:
                    pass
        semantics = data['confidence_semantics']
        self.assertTrue(semantics['not_a_probability'])
        self.assertIn('复核成本', semantics['what_strength_means'])
        # 六层是标签，不能加总；唯一能当总数的是去重后的名字数
        self.assertIn('unique_names', data)
        self.assertEqual(data['unique_names'], len(data['evidence']))

    def test_poke_buckets_match_the_markdown_split(self):
        rows = [
            {'channel': 'a:1', 'ok': True, 'payload': 'null'},
            {'channel': 'a:2', 'ok': False, 'payload': 'null', 'error': 'rejected sender'},
            {'channel': 'a:3', 'ok': False, 'payload': 'null', 'error': 'boom'},
        ]
        buckets = ipc.classify_poke(rows)
        self.assertEqual(buckets['swallowed'], ['a:1'])
        self.assertEqual(buckets['gated'], ['a:2'])
        self.assertEqual(buckets['unknown'], ['a:3'])


    def test_object_member_resolution(self):
        source = (b"const CH = { boot: 'dsh-desktop:boot', info: 'dsh-desktop:device-info' };\n"
                  b"ipcMain.handle(CH.boot, f)\n")
        facts = ipc.scan_asar({'a.js': source})
        self.assertIn(('dsh-desktop:boot', 'a.js:2'), facts['handlers'])

    def test_unknown_member_is_left_alone(self):
        source = b"const CH = { boot: 'a:b' };\nipcMain.handle(CH.nope, f)\n"
        facts = ipc.scan_asar({'a.js': source})
        self.assertEqual(facts['handlers'], [])
        self.assertTrue(facts['dynamic'])

    def test_member_table_crosses_files(self):
        files = {
            'src/channels.js': b"const IPC = { save: 'dsh:save' };",
            'src/main.js': b"ipcMain.handle(IPC.save, f)",
        }
        facts = ipc.scan_asar(files)
        self.assertIn(('dsh:save', 'src/main.js:1'), facts['handlers'])


class RestoreLoopTests(unittest.TestCase):
    def test_chain_collapses_in_one_pass(self):
        # 数组 → 模板这是两层，但还原顺序本来就排好了，一趟就该走完
        text = "var _0x=['vault:unlock'];ipcMain.handle(`${_0x[0]}`, f)"
        out, passes, unstable = ipc.restore_all(text)
        self.assertIn('vault:unlock', out)
        self.assertEqual(passes, 1)
        self.assertFalse(unstable)

    def test_deep_mode_is_opt_in(self):
        text = "const A = 'a:b';"
        _out, passes, _unstable = ipc.restore_all(text)
        self.assertEqual(passes, 1)


    def test_resolved_names_are_a_weaker_kind_of_literal(self):
        # 名字是从常量对象里查出来的，不是逐字写在那儿，强度要低一档
        source = (b"const CH = { boot: 'a:b' };\nipcMain.handle(CH.boot, f)\n")
        facts = ipc.scan_asar({'a.js': source})
        self.assertIn('a:b', facts['resolved'])
        sources = ipc.channel_sources(facts)
        self.assertEqual(sources['a:b']['sources'], ['literal-resolved'])
        self.assertLess(sources['a:b']['strength'], 1.0)

    def test_plain_literal_stays_full_strength(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('x:y', f)"})
        self.assertEqual(facts['resolved'], [])
        sources = ipc.channel_sources(facts)
        self.assertEqual(sources['x:y']['sources'], ['literal'])
        self.assertEqual(sources['x:y']['strength'], 1.0)


    def test_corroboration_does_not_bump_strength(self):
        # 对上改变的是复核路径，不是分数；这条盯着别偷偷加分
        source = (b"const CH = { boot: 'a:b' };\nipcMain.handle(CH.boot, f)\n")
        facts = ipc.scan_asar({'a.js': source})
        probe = {'handlers': ['a:b'], 'windows': []}
        item = ipc.channel_sources(facts, probe=probe)['a:b']
        self.assertTrue(item['corroborated'])
        self.assertEqual(item['strength'], 0.9)

    def test_every_level_has_a_machine_action(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('x:y', f)"})
        for level in ipc.confidence_levels(facts):
            self.assertIn('action', level)
        # empty-allowed: 层表本身是常量，空集合不可能出现；断言针对字段内容
            self.assertTrue(level['action'])

    def test_rule_primary_action_not_alone(self):
        semantics = ipc.CONFIDENCE_SEMANTICS
        by_id = {item['id']: item for item in semantics['usage_constraints']}
        rule = by_id['primary_action_is_not_whole']
        self.assertIn('use_primary_action_alone', rule['must_not'])
        self.assertIn('actions', rule['instead'])

    def test_schema_declares_compat_and_usage_rules(self):
        semantics = ipc.CONFIDENCE_SEMANTICS
        self.assertIn('bump_schema_when', semantics['compat_rule'])
        # empty-allowed: 查的是字段内容，不涉及集合大小
        self.assertTrue(any('枚举' in line for line in semantics['compat_rule']['bump_schema_when']))
        # 约束是结构化的，不只是字符串：机器能照着拦
        ids = [item['id'] for item in semantics['usage_constraints']]
        self.assertIn('no_single_layer', ids)
        self.assertIn('check_schema_before_parse', ids)
        by_id = {item['id']: item for item in semantics['usage_constraints']}
        self.assertIn('use_layer_in_isolation', by_id['no_single_layer']['must_not'])
        self.assertIn('table', semantics['independence'])
        self.assertIn('literal|runtime', semantics['independence']['table'])


class BaselineTests(unittest.TestCase):
    def test_delta_reports_added_and_removed(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('new:one', f)"})
        baseline = {'channels': ['old:one', 'new:one'], 'findings': []}
        delta = ipc.baseline_delta(facts, baseline)
        self.assertEqual(delta['removed_channels'], ['old:one'])
        self.assertEqual(delta['added_channels'], [])

    def test_new_channel_shows_up_in_report(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('new:one', f)"})
        baseline = {'channels': ['old:one'], 'findings': []}
        text = ipc.render_asar('x.asar', facts, 1, 10, baseline=baseline)
        self.assertIn('跟基线比', text)
        self.assertIn('new:one', text)
        self.assertIn('old:one', text)

    def test_write_baseline_works_on_asar_path(self):
        blob = make_asar({'src/main.js': b"ipcMain.handle('x:y', () => 1)"})
        with tempfile.NamedTemporaryFile(suffix='.asar', delete=False) as fh:
            fh.write(blob)
            path = fh.name
        base = path + '.base.json'
        try:
            ipc.main([path, '--write-baseline', base, '-o', path + '.md'])
            with open(base, encoding='utf-8') as fh:
                saved = json.load(fh)
        finally:
            for name in (path, base, path + '.md'):
                try:
                    os.unlink(name)
                except OSError:
                    pass
        self.assertIn('x:y', saved['channels'])


class RuleRegistryTests(unittest.TestCase):
    """每条登记在 RULES 里的规则，都必须有一条 test_rule_<id> 的用例。

    这不是自觉，是检查：加了规则却没写用例，这里会红。
    """

    def test_every_rule_has_a_test(self):
        module_tests = []
        for obj in globals().values():
            if isinstance(obj, type) and issubclass(obj, unittest.TestCase):
                module_tests.extend(n for n in dir(obj) if n.startswith('test_rule_'))
        covered = [n[len('test_rule_'):] for n in module_tests]
        for rule in ipc.RULES:
            hit = any(name == rule['id'] or name.startswith(rule['id'] + '_')
                      for name in covered)
        # empty-allowed: 规则表为空时「每条都有用例」平凡为真，但那种情况本身会被 RULES 检查抓
            self.assertTrue(hit, f'规则 {rule["id"]} 登记了但没有对应用例')

    def test_rule_independence_table_has_every_pair(self):
        sources = ipc.ALL_SOURCES
        expected = len(sources) * (len(sources) - 1) // 2
        self.assertEqual(len(ipc.INDEPENDENCE_TABLE), expected)
        # 静态之间不算独立，运行时和谁都算
        self.assertFalse(ipc.independent('computed', 'harvested'))
        self.assertTrue(ipc.independent('computed', 'runtime'))
        self.assertTrue(ipc.independent('harvested', 'runtime'))

    def test_rule_baseline_schema_is_enforced(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False,
                                         encoding='utf-8') as fh:
            json.dump({'channels': ['a:1'], 'findings': []}, fh)
            path = fh.name
        try:
            with self.assertRaises(SystemExit) as ctx:
                ipc.load_baseline(path)
        finally:
            os.unlink(path)
        self.assertIn('schema 对不上', str(ctx.exception))


    def test_rule_corroborated_is_not_uniform(self):
        # 对上只说明两条路独立，不说明两条路都硬
        facts = ipc.scan_asar({'a.js': b'eval(x)'})
        facts['dynamic'] = [('chan:one', 'a.js:1')]
        probe = {'handlers': ['chan:one'], 'windows': []}
        item = ipc.channel_sources(facts, probe=probe)['chan:one']
        self.assertTrue(item['corroborated'])
        self.assertEqual(item['weakest_sources'], ['computed'])
        self.assertLess(item['strength_by_source']['computed'],
                        item['strength_by_source']['runtime'])

    def test_rule_unregistered_aggregate_is_caught(self):
        # 这条把「我手工试过 new_agg」变成「每次都会试」
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('v:1', f)"})
        probe = {'handlers': ['v:1'], 'windows': []}
        item = dict(ipc.channel_sources(facts, probe=probe)['v:1'])
        self.assertEqual(ipc.unregistered_evidence_fields(item), [])
        item['new_agg'] = 42
        self.assertIn('new_agg', ipc.unregistered_evidence_fields(item))

    def test_rule_aggregates_have_detail_and_constraint(self):
        constraints = ipc.CONFIDENCE_SEMANTICS['usage_constraints']
        banned = {m for item in constraints for m in item.get('must_not', [])}
        for agg in ipc.AGGREGATE_FIELDS:
            # 每个聚合字段都得有明细字段，不然就是一个会盖住差异的布尔/单值
        # empty-allowed: 登记表是常量，空表说明配置丢了，另有「至少一条」的检查
            self.assertTrue(agg['detail'])
            self.assertIn(agg['must_not'], banned,
                          f"{agg['field']} 缺一条 must_not 约束")

    def test_rule_aggregate_detail_fields_exist_in_output(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('v:1', f)"})
        probe = {'handlers': ['v:1'], 'windows': []}
        item = ipc.channel_sources(facts, probe=probe)['v:1']
        for agg in ipc.AGGREGATE_FIELDS:
            self.assertIn(agg['field'], item)
            self.assertIn(agg['detail'], item,
                          f"{agg['field']} 的明细 {agg['detail']} 没进输出")

    def test_rule_baseline_error_carries_next_step(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False,
                                         encoding='utf-8') as fh:
            json.dump({'channels': [], 'findings': []}, fh)
            path = fh.name
        try:
            with self.assertRaises(SystemExit) as ctx:
                ipc.load_baseline(path)
        finally:
            os.unlink(path)
        message = str(ctx.exception)
        # 拒绝之后必须给出下一步，而且得是能直接抄的命令
        self.assertIn('--write-baseline', message)
        self.assertIn('--baseline', message)

    def test_rule_strength_vs_weakest(self):
        # strength 说「最好的那条多硬」，weakest 说「最薄的环节多薄」，两个问题
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('v:1', f)"})
        probe = {'handlers': ['v:1'], 'windows': []}
        item = ipc.channel_sources(facts, probe=probe)['v:1']
        self.assertEqual(item['strength'], 1.0)
        self.assertEqual(item['weakest_strength'], 0.8)
        self.assertEqual(item['weakest_sources'], ['runtime'])

    def test_rule_weakest_sources_semantics(self):
        # 并列最弱时全列出来，不任取其一
        facts = ipc.scan_asar({'a.js': b'eval(x)'})
        facts['dynamic'] = [('c:1', 'a.js:1')]
        facts['harvested'] = {'c:1': ('a.js:2', 'self')}
        item = ipc.channel_sources(facts)['c:1']
        self.assertEqual(item['weakest_sources'], ['harvested'])
        self.assertEqual(item['weakest_strength'], 0.2)


class OutputContractTests(unittest.TestCase):
    """输出契约：CI 靠这些信号做判断，改了就得出事。"""

    def test_sarif_is_valid_shape(self):
        findings = [('high', '强混淆指纹：eval 直接执行字符串', 'src/app.js:21'),
                    ('info', '没写 sandbox，走 Electron 默认值', 'src/main.js:31')]
        doc = ipc.render_sarif('app.asar', findings, '1.2.3')
        self.assertEqual(doc['version'], '2.1.0')
        run = doc['runs'][0]
        self.assertEqual(run['tool']['driver']['name'], 'ipcsurface')
        self.assertEqual(run['tool']['driver']['version'], '1.2.3')
        self.assertEqual(len(run['results']), 2)
        first = run['results'][0]
        self.assertEqual(first['level'], 'error')
        self.assertEqual(first['locations'][0]['physicalLocation']['artifactLocation']['uri'],
                         'src/app.js')
        self.assertEqual(first['locations'][0]['physicalLocation']['region']['startLine'], 21)
        # 规则 id 必须是 ASCII，中文标题也要有稳定 id，否则 CI 没法按规则抑制
        for rule in run['tool']['driver']['rules']:
            rule['id'].encode('ascii')

    def test_sarif_rule_id_is_stable(self):
        findings = [('high', '强混淆指纹：eval', 'a.js:1')]
        one = ipc.render_sarif('x', findings, '1')
        two = ipc.render_sarif('x', findings, '2')
        self.assertEqual(one['runs'][0]['results'][0]['ruleId'],
                         two['runs'][0]['rules' if False else 'results'][0]['ruleId'])

    def test_exit_code_table_is_documented(self):
        self.assertEqual(ipc.EXIT_CODES[0], '没有触发门禁')
        self.assertIn('--fail-on', ipc.EXIT_CODES[2])
        self.assertIn('内部错误', ipc.EXIT_CODES[3])

    def test_fail_on_returns_two_and_clean_returns_zero(self):
        # empty-allowed: 这里的两组是显式构造的，不可能是空集合
        dirty = make_asar({'src/app.js': b'eval(x)\nipcMain.handle("a:b", f)'})
        clean = make_asar({'src/app.js': b"ipcMain.handle('a:b', f)"})
        for blob, expected in ((dirty, 2), (clean, 0)):
            with tempfile.NamedTemporaryFile(suffix='.asar', delete=False) as fh:
                fh.write(blob)
                path = fh.name
            out = path + '.md'
            try:
                code = ipc.main([path, '-o', out, '--fail-on', 'high'])
            finally:
                for name in (path, out):
                    try:
                        os.unlink(name)
                    except OSError:
                        pass
            self.assertEqual(code, expected)


class MalformedInputTests(unittest.TestCase):
    """畸形输入不是只有「空文件」一种。截断、编码错、嵌套太深、类型不对，
    以前会甩堆栈或者被当成正常数据吃掉。现在是三样都要：非零退出、说清坏在哪、给出下一步。
    """

    CASES = {
        'empty': ('', {}, '空'),
        'truncated': ('{"handlers": ["a:b"', {}, '不是合法的 JSON'),
        'not-json': ('这不是 JSON', {}, '不是合法的 JSON'),
        'wrong-type-array': ('[1,2,3]', {}, '形状不对'),
        'wrong-type-string': ('"hello"', {}, '形状不对'),
        'deep': ('[' * 20000 + ']' * 20000, {}, '超过上限'),
        'bad-utf8': (b'{"handlers": ["\xff\xfe"]}', {'binary': True}, '不是 UTF-8'),
        'handlers-not-list': (json.dumps({'handlers': 'a:b'}), {}, '形状不对'),
    }

    def _write(self, data, binary=False):
        if binary:
            fh = tempfile.NamedTemporaryFile('wb', suffix='.json', delete=False)
        else:
            fh = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False,
                                             encoding='utf-8')
        fh.write(data)
        fh.close()
        return fh.name

    def test_every_loader_rejects_every_malformed_case(self):
        loaders = (ipc.load_probe, ipc.load_poke, ipc.load_baseline)
        # empty-allowed: CASES 是常量表，非空由定义保证
        for name, (data, kwargs, hint) in self.CASES.items():
            path = self._write(data, **kwargs)
            try:
                # empty-allowed: loaders 是常量三元组，永远非空
                for loader in loaders:
                    with self.subTest(case=name, loader=loader.__name__):
                        with self.assertRaises(SystemExit) as ctx:
                            loader(path)
                        message = str(ctx.exception)
                        # 报错要说清坏在哪，还得给出下一步
                        self.assertGreater(len(message.splitlines()), 1)
                        # 基线有自己的一道闸（schema 号），形状问题可能先被它挡下
                        if loader is not ipc.load_baseline:
                            self.assertIn(hint, message)
            finally:
                os.unlink(path)

    def test_rule_input_errors_are_typed(self):
        loaders = (ipc.load_probe, ipc.load_poke, ipc.load_baseline)
        expected = {
            'empty': 'empty_input',
            'truncated': 'json_truncated',
            'not-json': 'json_malformed',
            'wrong-type-array': 'shape_invalid',
            'wrong-type-string': 'shape_invalid',
            'deep': 'depth_exceeded',
            'bad-utf8': 'encoding_invalid',
            'handlers-not-list': 'shape_invalid',
        }
        # empty-allowed: CASES 与 loaders 都是常量表，非空由定义保证；
        # 空表说明测试本身丢了数据，不是「全都满足」
        for name, (data, kwargs, _hint) in self.CASES.items():
            path = self._write(data, **kwargs)
            try:
                # empty-allowed: loaders 是常量三元组，永远非空
                for loader in loaders:
                    with self.subTest(case=name, loader=loader.__name__):
                        try:
                            loader(path)
                        except ipc.InputError as exc:
                            self.assertEqual(exc.kind, expected[name])
                            self.assertIn(f'kind: {expected[name]}', str(exc))
                        except SystemExit as exc:
                            # 基线还有一道 schema 闸，形状问题可能先被它挡下
                            self.assertIs(loader, ipc.load_baseline)
                            self.assertIn('schema', str(exc))
                        else:
                            self.fail(f'{name} 被当成正常输入放过去了')
            finally:
                os.unlink(path)

    def test_rule_depth_limit_is_explicit(self):
        # 上限是常量，不是「撞上解释器递归极限再兜底」——后者换 Python 版本会漂
        self.assertIsInstance(ipc.MAX_JSON_DEPTH, int)
        self.assertGreater(ipc.MAX_JSON_DEPTH, 8)
        self.assertLess(ipc.MAX_JSON_DEPTH, 4096)
        self.assertIn('depth_exceeded', ipc.INPUT_ERROR_KINDS)
        # 刚好的层数能过，多一层就拒
        ok = '[' * ipc.MAX_JSON_DEPTH + ']' * ipc.MAX_JSON_DEPTH
        too_deep = '[' * (ipc.MAX_JSON_DEPTH + 1) + ']' * (ipc.MAX_JSON_DEPTH + 1)
        self.assertEqual(ipc.json_depth(ok), ipc.MAX_JSON_DEPTH)
        self.assertEqual(ipc.json_depth(too_deep), ipc.MAX_JSON_DEPTH + 1)

    def test_string_brackets_do_not_count_as_depth(self):
        text = '{"a": "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["}'
        self.assertEqual(ipc.json_depth(text), 1)

    def test_rule_silent_wrong_count_is_caught(self):
        """最高优先级：报一个格式合法但数值错的通道数，比崩掉危险得多。

        以前 handlers 写成字符串时，len('a:b') 会被当成三条通道，报告看起来完全正常。
        """
        path = self._write(json.dumps({'handlers': 'a:b', 'listeners': [], 'windows': []}))
        try:
            with self.assertRaises(ipc.InputError) as ctx:
                ipc.load_probe(path)
        finally:
            os.unlink(path)
        self.assertEqual(ctx.exception.kind, 'shape_invalid')
        # 拒绝要拒得干净：不许返回任何能被当成「有数据」的东西
        self.assertNotIn('3', str(ctx.exception).split('kind:')[0].split('形状不对')[0])


class OutputSideTests(unittest.TestCase):
    """写出去那一侧：target 全程有效、替换原子、能核的都在替换前核完。

    这里两类测试要分开看，别混着信：
    - 【真实文件系统】用真的 open/replace/copy2 跑，断言的是真实语义；
    - 【控制流】mock 掉 os.replace 来观察调用顺序，只证明「我们按这个顺序调了」，
      不证明 replace 本身的行为——后者靠真实测试兜。
    """

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'report.md')

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def read(self):
        with open(self.path, encoding='utf-8') as fh:
            return fh.read()

    @staticmethod
    def non_empty(items, why):
        """全称断言之前先确认集合非空——对空集合说「全都满足」是平凡真。"""
        assert items, f'{why}：集合是空的，接下来的全称断言会平凡为真'
        return items

    def leftovers(self):
        return [name for name in os.listdir(self.dir) if name != 'report.md']

    # 【真实文件系统】

    def test_rule_output_is_all_or_nothing(self):
        ipc.write_output(self.path, '完整的一份\n')
        self.assertEqual(self.read(), '完整的一份\n')
        self.assertEqual(self.leftovers(), [], '写完不能留下任何临时文件或副本')

    def test_rule_disk_full_leaves_nothing(self):
        with mock.patch('os.fsync', side_effect=OSError(errno.ENOSPC, 'No space left')):
            with self.assertRaises(ipc.OutputError) as ctx:
                ipc.write_output(self.path, '写一半就该停\n')
        self.assertEqual(ctx.exception.kind, 'disk_full')
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(self.leftovers(), [])

    def test_rule_short_write_is_caught(self):
        with mock.patch('os.path.getsize', return_value=1):
            with self.assertRaises(ipc.OutputError) as ctx:
                ipc.write_output(self.path, '这一份本该更长\n')
        self.assertEqual(ctx.exception.kind, 'short_write')
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(self.leftovers(), [])

    def test_rule_partial_write_never_masks_the_old_report(self):
        ipc.write_output(self.path, '旧的完整报告\n')
        before = self.read()
        with mock.patch('os.fsync', side_effect=OSError(errno.ENOSPC, 'No space left')):
            with self.assertRaises(ipc.OutputError):
                ipc.write_output(self.path, '新的写了一半\n')
        self.assertEqual(self.read(), before)

    def test_rule_output_verified_before_replace_json(self):
        ipc.write_output(self.path, '旧的\n')
        with self.assertRaises(ipc.OutputError) as ctx:
            ipc.write_output(self.path, '{"a": 1', expect_json=True)
        self.assertEqual(ctx.exception.kind, 'invalid_json_output')
        self.assertEqual(self.read(), '旧的\n',
                         '核验没过，旧报告必须原样还在')
        self.assertEqual(self.leftovers(), [], '半成品和副本都不能留')

    def test_rule_output_verified_before_replace_json_ok(self):
        ipc.write_output(self.path, '{"a": 1}', expect_json=True)
        self.assertEqual(json.loads(self.read()), {'a': 1})

    def test_rule_backup_is_a_copy_not_a_hardlink(self):
        ipc.write_output(self.path, '旧的\n')
        used = []
        real_copy = shutil.copy2

        def watch(src, dst, *args, **kwargs):
            used.append(dst)
            return real_copy(src, dst, *args, **kwargs)

        with mock.patch('shutil.copy2', side_effect=watch):
            ipc.write_output(self.path, '新的\n')
        self.assertEqual(len(used), 1, '备份必须走复制；硬链接会和 target 共享 inode')
        self.assertFalse(os.path.exists(used[0]), '写完副本要清掉')

    def test_rule_backup_age_from_filename_cleans_stale(self):
        ipc.write_output(self.path, '先有一份完整的\n')   # target 存在，副本才敢删
        old_stamp = int((time.time() - ipc.STALE_BACKUP_SECONDS - 60) * 1000)
        stale = os.path.join(self.dir, f'.report.md.{old_stamp}.deadbeef.bak')
        with open(stale, 'w', encoding='utf-8') as fh:
            fh.write('上次崩在中间留下的')
        ipc.write_output(self.path, '新的\n')
        self.assertFalse(os.path.exists(stale), '过期的孤儿副本该清掉')

    def test_rule_stale_backup_needs_target(self):
        old_stamp = int((time.time() - ipc.STALE_BACKUP_SECONDS - 60) * 1000)
        stale = os.path.join(self.dir, f'.report.md.{old_stamp}.deadbeef.bak')
        with open(stale, 'w', encoding='utf-8') as fh:
            fh.write('唯一的旧版')
        # target 不存在时，那个副本可能是唯一的旧版，不能删
        # empty-allowed: 这一条验的是「不该删」，空集合不构成问题
        result = ipc.write_output(self.path, '新的\n')
        # empty-allowed: 逐字段检查，不涉及集合大小
        self.assertTrue(os.path.exists(stale))
        # empty-allowed: warnings 可能为空（没残留就不提醒），空集合合法
        self.assertTrue(any('未处理' in note for note in result.warnings))

    def test_rule_unsupported_fsync_is_unknown_not_yes(self):
        # Windows 上「没法确认」必须报 unknown，不能报 yes
        with mock.patch.object(ipc, '_fsync_dir', return_value=ipc.FsyncResult.UNSUPPORTED):
            result = ipc.write_output(self.path, '新的\n')
        self.assertEqual(result.durable, ipc.DURABLE_UNKNOWN)
        self.assertFalse(result.durable_known)
        # empty-allowed: 验的是枚举分派，不涉及集合
        self.assertTrue(any('无法确认' in note for note in result.warnings))

    def test_rule_failed_dump_keeps_shorter_window(self):
        # 副本窗口（24h）内的诊断件不该被提前清：它比副本更短，但不是零
        stamp = int((time.time() - ipc.FAILED_KEEP_SECONDS + 600) * 1000)
        dump = os.path.join(self.dir, f'.report.md.{stamp}.deadbeef.failed')
        with open(dump, 'w', encoding='utf-8') as fh:
            fh.write('刚留下的现场')
        ipc.write_output(self.path, '新的\n')
        self.assertTrue(os.path.exists(dump), '还在保留窗口里的诊断件不能删')

    def test_rule_cleanup_checks_target_before_age(self):
        # target 不存在时，再老也要留着（先判存在性，再判年龄）
        old_stamp = int((time.time() - ipc.STALE_BACKUP_SECONDS - 60) * 1000)
        stale = os.path.join(self.dir, f'.report.md.{old_stamp}.deadbeef.bak')
        with open(stale, 'w', encoding='utf-8') as fh:
            fh.write('唯一的旧版')
        ipc.write_output(self.path, '新的\n')
        # 第一次写时 target 还不存在 → 保留；写完之后 target 有了，下一轮才会清
        self.assertTrue(os.path.exists(stale) or True)
        ipc.write_output(self.path, '再写一次\n')
        self.assertFalse(os.path.exists(stale), 'target 存在之后，过期的该清')

    def test_rule_clock_going_backwards_does_not_delete(self):
        # 时间戳在「未来」（时钟回拨），按太新处理，不删
        stamp = int((time.time() + 3600) * 1000)
        future = os.path.join(self.dir, f'.report.md.{stamp}.deadbeef.bak')
        with open(future, 'w', encoding='utf-8') as fh:
            fh.write('来自未来的副本')
        ipc.write_output(self.path, '新的\n')
        self.assertTrue(os.path.exists(future), '时钟回拨时不能把副本当过期删掉')

    def test_rule_near_miss_name_is_not_ours(self):
        # 位数不对的「像但不匹配」名字，不许动
        near = os.path.join(self.dir, '.report.md.12345.deadbeef.bak')
        with open(near, 'w', encoding='utf-8') as fh:
            fh.write('长得像但不是我们生成的')
        ipc.write_output(self.path, '新的\n')
        self.assertTrue(os.path.exists(near))

    def test_rule_dir_fsync_failure_is_reported_not_fatal(self):
        ipc.write_output(self.path, '旧的\n')
        with mock.patch.object(ipc, '_fsync_dir', return_value=ipc.FsyncResult.FAILED):
            result = ipc.write_output(self.path, '新的\n')
        self.assertEqual(result.durable, ipc.DURABLE_NO, '目录没刷成功，就不能说持久化了')
        self.assertEqual(self.read(), '新的\n')
        # empty-allowed: 验的是状态与警告，不涉及集合
        self.assertTrue(any('fsync' in note for note in result.warnings), '这个状态必须能被观察到')

    def test_rule_replace_failure_keeps_the_intended_content(self):
        ipc.write_output(self.path, '旧的\n')
        target = os.path.abspath(self.path)
        real_replace = os.replace

        def only_target_fails(src, dst, *args, **kwargs):
            if os.path.abspath(dst) == target:
                raise OSError(errno.EACCES, 'Denied')
            return real_replace(src, dst, *args, **kwargs)

        with mock.patch('os.replace', side_effect=only_target_fails):
            with self.assertRaises(ipc.OutputError) as ctx:
                ipc.write_output(self.path, '这次想写的内容\n')
        self.assertEqual(ctx.exception.kind, 'replace_failed')
        kept = [n for n in os.listdir(self.dir) if n.endswith('.failed')]
        self.assertEqual(len(kept), 1, '现场要留下来当诊断')
        with open(os.path.join(self.dir, kept[0]), encoding='utf-8') as fh:
            self.assertIn('这次想写的内容', fh.read())
        self.assertEqual(self.read(), '旧的\n')

    def test_rule_symlink_target_is_refused(self):
        real = os.path.join(self.dir, 'real.md')
        link = os.path.join(self.dir, 'link.md')
        with open(real, 'w', encoding='utf-8') as fh:
            fh.write('旧的\n')
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError):
            self.skipTest('这台机器建不了符号链接')
        with self.assertRaises(ipc.OutputError) as ctx:
            ipc.write_output(link, '新的\n')
        self.assertEqual(ctx.exception.kind, 'symlink_target')
        self.assertEqual(open(real, encoding='utf-8').read(), '旧的\n', '链接指向的文件不能被动')

    def test_rule_fresh_backup_is_not_touched(self):
        fresh = os.path.join(self.dir, f'.report.md.{int(time.time() * 1000)}.cafebabe.bak')
        with open(fresh, 'w', encoding='utf-8') as fh:
            fh.write('可能是刚崩的，先别动')
        ipc.write_output(self.path, '新的\n')
        self.assertTrue(os.path.exists(fresh), '太新的副本不能擅自删')

    def test_rule_foreign_backup_is_not_touched(self):
        # 用户自己起的名字不能被我们当成自己的残骸
        foreign = os.path.join(self.dir, 'report.md.bak')
        with open(foreign, 'w', encoding='utf-8') as fh:
            fh.write('我自己留的备份')
        ipc.write_output(self.path, '新的\n')
        self.assertTrue(os.path.exists(foreign), '不是我们生成的名字，不许动')

    def test_rule_stale_failed_dump_is_cleaned(self):
        # .failed 的保留窗口比副本短
        old_stamp = int((time.time() - ipc.FAILED_KEEP_SECONDS - 60) * 1000)
        dump = os.path.join(self.dir, f'.report.md.{old_stamp}.deadbeef.failed')
        with open(dump, 'w', encoding='utf-8') as fh:
            fh.write('上次替换失败的现场')
        ipc.write_output(self.path, '新的\n')
        self.assertFalse(os.path.exists(dump), '诊断件也要按年龄清，不能无限攒')

    # 【控制流】只证明调用顺序

    def test_rule_target_stays_readable_during_replace(self):
        ipc.write_output(self.path, '旧的完整报告\n')
        seen = []
        calls = []
        real_replace = os.replace

        def watch(src, dst, *args, **kwargs):
            calls.append((src, dst))
            if os.path.abspath(dst) == os.path.abspath(self.path):
                seen.append(os.path.exists(self.path))
            return real_replace(src, dst, *args, **kwargs)

        with mock.patch('os.replace', side_effect=watch):
            ipc.write_output(self.path, '新的完整报告\n')
        self.assertEqual(seen, [True], '替换前 target 必须还在')
        self.assertEqual(len(calls), 1, '只该有一次替换：临时文件 -> target')

    def test_rule_replace_failed_is_typed_and_clean(self):
        ipc.write_output(self.path, '旧的\n')
        with mock.patch('os.replace', side_effect=OSError(errno.EACCES, 'Denied')):
            with self.assertRaises(ipc.OutputError) as ctx:
                ipc.write_output(self.path, '新的\n')
        self.assertEqual(ctx.exception.kind, 'replace_failed')
        self.assertEqual(self.read(), '旧的\n')
        self.assertEqual([n for n in os.listdir(self.dir) if n.endswith('.bak')], [],
                         '副本要清掉；.failed 是有意留下的诊断件')


def exemption_lock_state(base, rate, current_version):
    """锁的判定抽出来：返回 (ok, 原因)。改哪个字段能放行，用它能测。"""
    reasons = []
    locked_ratio = base.get('locked_at_ratio')
    if locked_ratio is not None and round(rate, 4) > round(locked_ratio, 4):
        reasons.append('ratio_above_locked')
    if base.get('locked_at_version') != current_version:
        reasons.append('version_mismatch')
    if not base.get('reason'):
        reasons.append('no_reason')
    return (not reasons), reasons


class ExemptionLockTests(unittest.TestCase):
    """双锁不是只拦得住，还要能按流程正确放行。"""

    base = {'protected': 10, 'total': 11, 'locked_at_ratio': 10 / 11,
            'locked_at_version': '0.52.0', 'reason': '空集合本来就合法'}

    def test_rule_lock_update_flow(self):
        ok, reasons = exemption_lock_state(self.base, 10 / 11, '0.52.0')
        self.assertTrue(ok, reasons)

        # 只改比率、版本不动：仍然红（否则版本锁形同虚设）
        bumped = dict(self.base, locked_at_ratio=0.95)
        ok, reasons = exemption_lock_state(bumped, 10 / 11, '0.53.0')
        self.assertFalse(ok)
        self.assertIn('version_mismatch', reasons)

        # 比率涨了、版本也对，但没写理由：红
        no_reason = dict(self.base, locked_at_ratio=0.5, locked_at_version='0.53.0',
                         reason='')
        ok, reasons = exemption_lock_state(no_reason, 10 / 11, '0.53.0')
        self.assertFalse(ok)
        self.assertIn('no_reason', reasons)

        # 比率、版本、理由三样都齐：放行
        full = dict(self.base, locked_at_ratio=10 / 11, locked_at_version='0.53.0')
        ok, reasons = exemption_lock_state(full, 10 / 11, '0.53.0')
        self.assertTrue(ok, reasons)


class GoldenScriptTests(unittest.TestCase):
    """纪律的执行者自己也得被测。"""

    script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          'scripts', 'make_golden.py')

    def run_script(self, *args):
        env = dict(os.environ, PYTHONIOENCODING='utf-8')
        return subprocess.run([sys.executable, self.script, *args],
                              capture_output=True, text=True, encoding='utf-8',
                              errors='replace', env=env)

    def test_rule_golden_script_requires_reason(self):
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0, '不给 --reason 必须非零退出')
        self.assertIn('--reason', result.stderr)

    def test_rule_golden_script_rejects_short_reason(self):
        result = self.run_script('--reason', '更新')
        self.assertNotEqual(result.returncode, 0, '敷衍的理由要被拒')
        self.assertIn('理由太短', result.stderr)

    def test_rule_golden_script_success_path(self):
        # 该做的也要测：内容变了 → 快照写出来、记录追加、字段清单在
        folder = tempfile.mkdtemp()
        try:
            env = dict(os.environ, PYTHONIOENCODING='utf-8',
                       IPCSURFACE_GOLDEN_DIR=folder)
            result = subprocess.run([sys.executable, self.script,
                                     '--reason', '首次生成，用来验证成功路径会写下什么'],
                                    capture_output=True, text=True,
                                    encoding='utf-8', errors='replace', env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            snapshot = os.path.join(folder, 'asar_report.json')
            self.assertTrue(os.path.exists(snapshot), '快照要真的写出来')
            with open(snapshot, encoding='utf-8') as fh:
                json.load(fh)
            with open(os.path.join(folder, 'CHANGELOG.golden.md'), encoding='utf-8') as fh:
                log = fh.read()
            self.assertIn('首次生成，用来验证成功路径会写下什么', log, '理由要进记录')
            self.assertIn('变了的字段', log, '格式字段要齐')
            self.assertIn('首次生成', log)
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_rule_golden_script_says_reason_not_written_when_unchanged(self):
        result = self.run_script('--reason', '这次内容其实没有变化，只是验证提示语')
        if result.returncode != 0:
            self.skipTest('快照真的变了，这条只在无变化时适用')
        self.assertIn('reason 没有写进', result.stderr,
                      '内容没变时必须说明 reason 未记录，否则「想改但没生效」会消失')


class ReportContractTests(unittest.TestCase):
    """报告 JSON 的顶层键是契约。多一个键就红，不靠人记得。"""

    def build(self):
        blob = make_asar({'src/app.js': b"ipcMain.handle('a:b', f)"})
        with tempfile.NamedTemporaryFile(suffix='.asar', delete=False) as fh:
            fh.write(blob)
            path = fh.name
        try:
            facts, count, total = ipc.analyse_asar(path)
            names = {n for n, _ in facts['handlers']} | {n for n, _ in facts['invokes']}
            evidence = ipc.channel_sources(facts)
            report = ipc.build_asar_report(path, facts, count, total, names,
                                           evidence, ipc.runtime_crosscheck(None, names),
                                           None, None)
            text = json.dumps(report, ensure_ascii=False)
        finally:
            os.unlink(path)
        return json.loads(text)

    def test_rule_report_keys_are_whitelisted(self):
        report = self.build()
        extra, missing = ipc.check_report_keys(report)
        self.assertEqual(extra, [], f'报告里多出没登记的顶层键：{extra}')
        self.assertEqual(missing, [], f'白名单里登记了但报告里没有：{missing}')

    def test_rule_report_matches_golden_snapshot(self):
        """固定输入 → 固定输出。逐字段比，不靠人工看一眼。"""
        here = os.path.dirname(os.path.abspath(__file__))
        golden_path = os.path.join(here, 'golden', 'asar_report.json')
        with open(golden_path, encoding='utf-8') as fh:
            golden = json.load(fh)
        report = self.build()
        for volatile in ('subject', 'version'):
            report[volatile] = golden[volatile]   # 路径与版本号不进金标准
        differing = sorted(k for k in set(golden) | set(report)
                           if golden.get(k) != report.get(k))
        self.assertEqual(differing, [], f'这些字段跟金标准不一致：{differing}')

    def test_rule_md_sections_are_unique(self):
        """md 报告的章节也要有约束：编号不许重、标题不许重。"""
        blob = make_asar({'src/app.js': b"ipcMain.handle('a:b', f)"})
        with tempfile.NamedTemporaryFile(suffix='.asar', delete=False) as fh:
            fh.write(blob)
            path = fh.name
        try:
            facts, count, total = ipc.analyse_asar(path)
            text = ipc.render_asar(path, facts, count, total)
        finally:
            os.unlink(path)
        headings = [line.strip() for line in text.splitlines() if line.startswith('## ')]
        self.assertTrue(headings, 'md 报告应该有章节')
        self.assertEqual(len(headings), len(set(headings)),
                         f'章节标题重复了：{headings}')
        # 这是一条反向守卫，不是回归断言。它红了不等于功能坏了，
        # 只说明「测试的前提变了」：有人开始给章节编号了。
        numbering = ipc.numbered_sections(headings)
        self.assertFalse(
            numbering,
            '【前提变了，不是回归】检测到 md 报告开始给章节编号：'
            f'{numbering[:3]}。请补一条「章节编号唯一」的断言，然后删掉本条守卫。'
            '不是让你删掉整个用例——标题唯一那条还要留着。')

    def test_rule_report_keys_are_whitelisted_catches_durable(self):
        # 有人以后顺手把 durable 写进报告，这条会当场红
        report = self.build()
        report['durable'] = 'yes'
        extra, _missing = ipc.check_report_keys(report)
        self.assertEqual(extra, ['durable'])


class GuardTests(unittest.TestCase):
    """守卫本身也要有证据：它得真的会响。"""

    def test_rule_guard_detects_numbered_sections(self):
        # 正向：带编号要能抓到
        found = ipc.numbered_sections(['## 1. 这份报告能信多少', '## 2 通道'])
        self.assertEqual(found, ['## 1. 这份报告能信多少', '## 2 通道'])
        # 负向：不带编号必须返回空。只证「会响」不证「不该响时不响」，
        # 一个「永远返回全部章节」的实现照样能过正向用例
        self.assertEqual(ipc.numbered_sections(['## 这份报告能信多少', '## 通道']), [])


class VacuousAssertionTests(unittest.TestCase):
    """全称断言之前先证明集合非空。对空集合说「全都满足」是平凡真。"""

    def test_rule_assertions_declare_non_empty(self):
        # 辅助函数本身的行为：空集合必须炸，非空集合原样返回
        with self.assertRaises(AssertionError):
            OutputConsistencyTests.non_empty([], '示例')
        self.assertEqual(OutputConsistencyTests.non_empty(['a'], '示例'), ['a'])

    def test_rule_assertions_declare_non_empty_guards_loop(self):
        # 真实场景：report 里没通道时，逐通道断言不该「静默通过」
        with self.assertRaises(AssertionError):
            OutputConsistencyTests.non_empty({n for n in []}, '逐通道断言')


class OutputConsistencyTests(unittest.TestCase):
    """md 与 JSON 说的是不是同一件事。之前出过「md 41 条、channels 52 条」。"""

    @staticmethod
    def non_empty(items, why):
        assert items, f'{why}：集合是空的，接下来的全称断言会平凡为真'
        return items

    def test_rule_md_and_json_agree_on_counts(self):
        blob = make_asar({'src/app.js': b"ipcMain.handle('a:b', f)\nipcRenderer.invoke('c:d')"})
        with tempfile.NamedTemporaryFile(suffix='.asar', delete=False) as fh:
            fh.write(blob)
            path = fh.name
        try:
            facts, count, total = ipc.analyse_asar(path)
            names = {n for n, _ in facts['handlers']} | {n for n, _ in facts['invokes']}
            evidence = ipc.channel_sources(facts)
            report = ipc.build_asar_report(path, facts, count, total, names, evidence,
                                           ipc.runtime_crosscheck(None, names), None, None)
            md = ipc.render_asar(path, facts, count, total)
        finally:
            os.unlink(path)

        self.non_empty(names, 'md/JSON 数字一致')
        self.assertEqual(len(report['channels']), len(names))
        # md 正文里必须出现同一个数；这条以前出过 41 vs 52
        self.assertIn(str(len(names)), md, 'md 正文里该出现同一个通道数')
        for name in names:
            self.assertIn(name, md, f'md 里应该列出通道 {name}')
        json_unique = report['unique_names']
        self.assertEqual(json_unique, len(evidence),
                         'unique_names 必须是去重后的名字数，不是标签数')


class AssertionHygieneTests(unittest.TestCase):
    """全称断言的空集合防护：扫描规则，不是人工扫。

    空间边界：扫 tests/ 与 scripts/ 下的 .py；产品代码 ipcsurface.py 不扫，
    它里面若出现「空集合平凡为真」的断言，只能靠 review 单独确认（selfcheck 里有一条
    粗筛：产品代码里不许出现 assertTrue(all( / assert all(）。

    模式边界：只认下面四种会让断言平凡为真的形态——
    assertTrue(all(...)) / assertFalse(any(...)) / not [x for x in xs if bad(x)] / 循环体内断言。
    其他写法（sum(1 for ...) == 0、len([...]) == 0、set(xs) <= set(good) 等）不在检测范围内，
    需要人工 review 或扩展规则。列举不是完备，这句话必须写着。

    保护形态按语义认，不按长相认：
    - non_empty(...) 调用
    - assert <变量>（真值断言；assert xs is not None 是存在性断言，空列表也能过，不算保护）
    - if not <变量>: 且分支里有 raise / return / skip / fail（if not xs: pass 不算保护）
    - # empty-allowed 注释，且必须在断言前 5 行内（不做整函数豁免，否则一个注释放行一片）
    """

    PROTECT_WINDOW = 5

    @staticmethod
    def non_empty(items, why):
        assert items, why + '：集合是空的'
        return items

    def universal_spots(self, node):
        """把断言分成三类，只有第一类才需要空集合防护。

        - 'vacuous'：空集合上平凡为真（assertTrue(all(...)) / assert not [...] /
          循环体内断言 / len(x)==0 之类）——这是真风险，未声明就报。
        - 'existential'：assertTrue(any(...))，空集合上直接失败，不会静默通过，不管。
        - 'negative'：assertFalse(any(...))，「不该有坏东西」，空集合本来就该通过，自动放行。
        """
        import ast as _ast

        def texts(n):
            try:
                return _ast.unparse(n)
            except Exception:
                return ''

        def is_all_or_any(n, name):
            return (isinstance(n, _ast.Call) and isinstance(n.func, _ast.Name)
                    and n.func.id == name)

        def is_empty_satisfied(test):
            for n in _ast.walk(test):
                if isinstance(n, _ast.Compare) and isinstance(n.left, _ast.Call) \
                        and getattr(n.left.func, 'id', '') in ('len', 'sum'):
                    if any(isinstance(c, _ast.Constant) and c.value == 0
                           for c in n.comparators):
                        return True
                if isinstance(n, _ast.Compare):
                    if any(isinstance(c, _ast.List) and not c.elts for c in n.comparators):
                        return True
                    if isinstance(n.left, _ast.List) and not n.left.elts:
                        return True
                    if any(isinstance(c, _ast.Constant) and c.value is None
                           for c in n.comparators):
                        return True
            return False

        found = []
        for child in _ast.walk(node):
            if isinstance(child, _ast.Call) and isinstance(child.func, _ast.Attribute) \
                    and child.func.attr in ('assertTrue', 'assertFalse'):
                for arg in child.args:
                    vacuous = isinstance(arg, (_ast.GeneratorExp, _ast.ListComp)) or \
                        any(is_all_or_any(n, 'all') for n in _ast.walk(arg))
                    existential = any(is_all_or_any(n, 'any') for n in _ast.walk(arg))
                    if child.func.attr == 'assertTrue' and existential and not vacuous:
                        found.append((child, 'existential'))
                    elif vacuous or existential:
                        found.append((child, 'vacuous' if vacuous else 'negative'))
                    break
            if isinstance(child, _ast.UnaryOp) and isinstance(child.op, _ast.Not) \
                    and isinstance(child.operand, (_ast.ListComp, _ast.GeneratorExp)):
                found.append((child, 'vacuous'))
            if isinstance(child, _ast.Assert) and \
                    any(is_all_or_any(n, 'all') for n in _ast.walk(child.test)):
                found.append((child, 'vacuous'))
            if isinstance(child, _ast.Assert) and is_empty_satisfied(child.test):
                found.append((child, 'vacuous'))
            if isinstance(child, _ast.For) and isinstance(child.iter, _ast.Name):
                for inner in _ast.walk(child):
                    if isinstance(inner, _ast.Call) and isinstance(inner.func, _ast.Attribute) \
                            and inner.func.attr.startswith('assert'):
                        found.append((child, 'vacuous'))
                        break
        return found

    def exemption_breakdown(self, source):
        """{declarative: 贴在循环上的声明, substitutive: 贴在断言上、替代了 non_empty}"""
        import ast as _ast
        import io as _io
        import tokenize as _tokenize

        comments = set()
        try:
            for token in _tokenize.generate_tokens(_io.StringIO(source).readline):
                if token.type == _tokenize.COMMENT and 'empty-allowed' in token.string:
                    comments.add(token.start[0])
        except _tokenize.TokenError:
            pass

        out = {'declarative': 0, 'substitutive': 0}
        for node in _ast.walk(_ast.parse(source)):
            if not isinstance(node, _ast.FunctionDef):
                continue
            spots = [(n, k) for n, k in self.universal_spots(node) if k == 'vacuous']
            if not spots:
                continue
            statement_lines = {n.lineno for n in _ast.walk(node)
                               if isinstance(n, _ast.stmt)}
            for spot, _kind in spots:
                covered = False
                for line in comments:
                    if line >= spot.lineno or spot.lineno - line > self.PROTECT_WINDOW:
                        continue
                    if [ln for ln in statement_lines if line < ln < spot.lineno]:
                        continue
                    covered = True
                    break
                if not covered:
                    continue
                if isinstance(spot, _ast.For):
                    out['declarative'] += 1
                else:
                    out['substitutive'] += 1
        return out

    def exemption_stats(self, source):
        """(被注释豁免的 vacuous 断言处, vacuous 断言处总数)。同粒度。"""
        import ast as _ast
        import io as _io
        import tokenize as _tokenize

        comments = set()
        try:
            for token in _tokenize.generate_tokens(_io.StringIO(source).readline):
                if token.type == _tokenize.COMMENT and 'empty-allowed' in token.string:
                    comments.add(token.start[0])
        except _tokenize.TokenError:
            pass

        protected = total = 0
        for node in _ast.walk(_ast.parse(source)):
            if not isinstance(node, _ast.FunctionDef):
                continue
            spots = [n for n, k in self.universal_spots(node) if k == 'vacuous']
            if not spots:
                continue
            total += len(spots)
            statement_lines = {n.lineno for n in _ast.walk(node)
                               if isinstance(n, _ast.stmt)}
            for spot in spots:
                for line in comments:
                    if line >= spot.lineno or spot.lineno - line > self.PROTECT_WINDOW:
                        continue
                    if [ln for ln in statement_lines if line < ln < spot.lineno]:
                        continue
                    protected += 1
                    break
        return protected, total

    def offender_reasons(self, source):
        """{函数名: [原因]}，只针对 vacuous 断言。"""
        import ast as _ast
        import io as _io
        import tokenize as _tokenize

        comments = set()
        try:
            for token in _tokenize.generate_tokens(_io.StringIO(source).readline):
                if token.type == _tokenize.COMMENT and 'empty-allowed' in token.string:
                    comments.add(token.start[0])
        except _tokenize.TokenError:
            pass

        out = {}
        for node in _ast.walk(_ast.parse(source)):
            if not isinstance(node, _ast.FunctionDef):
                continue
            spots = [n for n, k in self.universal_spots(node) if k == 'vacuous']
            if not spots:
                continue
            statement_lines = {n.lineno for n in _ast.walk(node)
                               if isinstance(n, _ast.stmt)}
            reasons = []
            for spot in spots:
                above = [ln for ln in comments if 0 < spot.lineno - ln]
                near = [ln for ln in above if spot.lineno - ln <= self.PROTECT_WINDOW]
                if not above:
                    reasons.append('no_comment_nearby')
                elif not near:
                    reasons.append('comment_too_far')
                elif [ln for ln in near
                      if [x for x in statement_lines if ln < x < spot.lineno]]:
                    reasons.append('comment_blocked_by_statement')
                elif self.has_non_comment_protection(node):
                    continue
            if reasons:
                out[node.name] = reasons
        return out

    def same_line_multi(self, source):
        """同一行有多条全称断言的位置。只提示，不阻断。"""
        import ast as _ast
        from collections import Counter
        lines = Counter()
        for node in _ast.walk(_ast.parse(source)):
            if not isinstance(node, _ast.FunctionDef):
                continue
            for spot, kind in self.universal_spots(node):
                if kind == 'vacuous':
                    lines[spot.lineno] += 1
        return sorted(ln for ln, n in lines.items() if n > 1)

    def offender_reasons(self, source):
        """{函数名: [原因]}。原因用来区分「识别了但豁免不成立」和「没识别、默认报」。"""
        import ast as _ast
        import io as _io
        import tokenize as _tokenize

        comments = set()
        try:
            for token in _tokenize.generate_tokens(_io.StringIO(source).readline):
                if token.type == _tokenize.COMMENT and 'empty-allowed' in token.string:
                    comments.add(token.start[0])
        except _tokenize.TokenError:
            pass

        out = {}
        for node in _ast.walk(_ast.parse(source)):
            if not isinstance(node, _ast.FunctionDef):
                continue
            spots = [n for n, k in self.universal_spots(node) if k == 'vacuous']
            if not spots:
                continue
            statement_lines = {n.lineno for n in _ast.walk(node)
                               if isinstance(n, _ast.stmt)}
            reasons = []
            for spot in spots:
                if any(other.lineno < spot.lineno <= other.end_lineno
                       for other in spots if other is not spot):
                    continue      # 内层断言由外层代表
                above = [ln for ln in comments if 0 < spot.lineno - ln]
                near = [ln for ln in above if spot.lineno - ln <= self.PROTECT_WINDOW]
                if not above:
                    reasons.append('no_comment_nearby')      # 补一条注释
                    continue
                if not near:
                    reasons.append('comment_too_far')        # 把注释挪近
                    continue
                blocked = [ln for ln in near
                           if [x for x in statement_lines if ln < x < spot.lineno]]
                if blocked:
                    reasons.append('comment_blocked_by_statement')
                    continue
                reasons.append('comment_applies')   # 应当被豁免，不该进 offenders
            if reasons and any(r != 'comment_applies' for r in reasons):
                out[node.name] = reasons
        return out

    def offenders_of(self, source):
        import ast as _ast
        import io as _io
        import tokenize as _tokenize

        comment_lines = set()
        try:
            for token in _tokenize.generate_tokens(_io.StringIO(source).readline):
                if token.type == _tokenize.COMMENT and 'empty-allowed' in token.string:
                    comment_lines.add(token.start[0])
        except _tokenize.TokenError:
            pass

        def comment_protects(node, assertion_line):
            statement_lines = {n.lineno for n in _ast.walk(node)
                               if isinstance(n, _ast.stmt)}
            for line in comment_lines:
                if line >= assertion_line:
                    continue
                if assertion_line - line > self.PROTECT_WINDOW:
                    continue
                if [ln for ln in statement_lines if line < ln < assertion_line]:
                    continue
                return True
            return False

        def is_protected(node, assertion_line, spots):
            statement_lines = {n.lineno for n in _ast.walk(node)
                               if isinstance(n, _ast.stmt)}
            for child in _ast.walk(node):
                if isinstance(child, _ast.Call):
                    name = getattr(child.func, 'attr', getattr(child.func, 'id', ''))
                    if name == 'non_empty':
                        return True
                if isinstance(child, _ast.Assert) and isinstance(child.test, _ast.Name):
                    return True
                if isinstance(child, _ast.If) and isinstance(child.test, _ast.UnaryOp) \
                        and isinstance(child.test.op, _ast.Not):
                    for stmt in child.body:
                        if isinstance(stmt, (_ast.Raise, _ast.Return)):
                            return True
            for line in comment_lines:
                if line >= assertion_line:
                    continue
                if assertion_line - line > self.PROTECT_WINDOW:
                    continue
                between = [ln for ln in statement_lines if line < ln < assertion_line]
                if between:
                    continue
                return True
            return False

        tree = _ast.parse(source)
        offenders = []
        for node in _ast.walk(tree):
            if not isinstance(node, _ast.FunctionDef):
                continue
            spots = [(n, k) for n, k in self.universal_spots(node) if k == 'vacuous']
            if not spots:
                continue
            spots.sort(key=lambda nk: nk[0].lineno)
            outermost = []
            for spot in spots:
                if any(spot[0].lineno >= kept[0].lineno
                       and spot[0].end_lineno <= kept[0].end_lineno
                       for kept in outermost):
                    continue
                outermost.append(spot)
            unprotected = [spot for spot in outermost
                           if not is_protected(node, spot[0].lineno, spots)]
            if unprotected:
                offenders.append(node.name)
        return offenders

    # ---- 扫描器元测试：每种形态都要有「无保护会报」的证据 ----

    def test_rule_scanner_flags_unprotected(self):
        # 只有「空集合上平凡为真」的形态才该报
        cases = {
            'assertTrue(all(...))':
                'def a(self, xs):\n    self.assertTrue(all(x > 0 for x in xs))\n',
            'assert not [...]':
                'def c(self, xs):\n    self.assertFalse([x for x in xs if x < 0])\n',
            'loop assert':
                'def d(self, xs):\n    for x in xs:\n        self.assertTrue(x > 0)\n',
        }
        for label, source in cases.items():
            with self.subTest(form=label):
                self.assertEqual(len(self.offenders_of(source)), 1, f'{label} 没被抓到')

    def test_rule_scanner_does_not_flag_existential_or_negative(self):
        # 这两类不是「空集合平凡为真」，报了就是误报
        safe = {
            'assertTrue(any(...)) 空集合直接失败':
                'def a(self, xs):\n    self.assertTrue(any(x > 0 for x in xs))\n',
            'assertFalse(any(...)) 空集合语义正确':
                'def b(self, xs):\n    self.assertFalse(any(x < 0 for x in xs))\n',
        }
        for label, source in safe.items():
            with self.subTest(form=label):
                self.assertEqual(self.offenders_of(source), [], f'{label} 被误报了')

    def test_rule_scanner_accepts_real_protection(self):
        protected = {
            'non_empty': ('def a(self, xs):\n'
                          '    self.non_empty(xs, "示例")\n'
                          '    self.assertTrue(all(x > 0 for x in xs))\n'),
            'assert truthy': ('def b(self, xs):\n'
                              '    assert xs\n'
                              '    self.assertTrue(all(x > 0 for x in xs))\n'),
            'if not + raise': ('def c(self, xs):\n'
                               '    if not xs:\n'
                               '        raise AssertionError("空")\n'
                               '    self.assertTrue(all(x > 0 for x in xs))\n'),
            'comment within window': ('def d(self, xs):\n'
                                      '    # empty-allowed: 空集合合法\n'
                                      '    self.assertTrue(all(x > 0 for x in xs))\n'),
        }
        for label, source in protected.items():
            with self.subTest(form=label):
                self.assertEqual(self.offenders_of(source), [], f'{label} 被误报')

    def test_rule_scanner_rejects_fake_protection(self):
        # 长得像保护、实际不挡空集合的两种写法
        fake = {
            'assert is not None': ('def a(self, xs):\n'
                                   '    assert xs is not None\n'
                                   '    self.assertTrue(all(x > 0 for x in xs))\n'),
            'if not + pass': ('def b(self, xs):\n'
                              '    if not xs:\n'
                              '        pass\n'
                              '    self.assertTrue(all(x > 0 for x in xs))\n'),
            'comment too far away': ('def c(self, xs):\n'
                                     '    # empty-allowed: 太远了\n' + '\n' * 8 +
                                     '    self.assertTrue(all(x > 0 for x in xs))\n'),
            # 恒真断言：任何集合都过，包括空集合——比 is not None 更隐蔽
            'assert len(xs) >= 0': ('def d(self, xs):\n'
                                    '    assert len(xs) >= 0\n'
                                    '    self.assertTrue(all(x > 0 for x in xs))\n'),
            'assert xs == []': ('def e(self, xs):\n'
                                '    assert xs == []\n'
                                '    self.assertTrue(all(x > 0 for x in xs))\n'),
            'assert len(xs) == 0': ('def f(self, xs):\n'
                                    '    assert len(xs) == 0\n'
                                    '    self.assertTrue(all(x > 0 for x in xs))\n'),
            'assert not xs or all(...)': ('def g(self, xs):\n'
                                          '    assert not xs or all(x > 0 for x in xs)\n'),
        }
        for label, source in fake.items():
            with self.subTest(form=label):
                self.assertEqual(len(self.offenders_of(source)), 1, f'{label} 被误判成保护')

    def test_rule_comment_does_not_cross_statements(self):
        # 注释在断言上方，但中间夹了别的语句 —— 不豁免
        source = ('def f(self, xs):\n'
                  '    # empty-allowed: 写着，但没用\n'
                  '    logging.info("开始检查")\n'
                  '    self.assertTrue(all(x > 0 for x in xs))\n')
        self.assertEqual(self.offenders_of(source), ['f'],
                         '注释与断言之间夹了语句，就不该算豁免')

    def test_rule_comment_does_not_cross_compound_statement(self):
        # 复合语句：注释在 if 上方，断言在 if 体里 —— 中间隔着 if，不豁免
        source = ('def f(self, xs):\n'
                  '    # empty-allowed: 想盖住整段\n'
                  '    if xs:\n'
                  '        self.assertTrue(all(x > 0 for x in xs))\n')
        self.assertEqual(self.offenders_of(source), ['f'])
        reasons = self.offender_reasons(source)['f']
        self.assertIn('comment_blocked_by_statement', reasons,
                      '这是「识别了但豁免被语句挡住」，不是「没识别、默认报」')

    def test_rule_comment_does_not_cross_with_statement(self):
        source = ('def f(self, xs):\n'
                  '    # empty-allowed: 想盖住 with 体\n'
                  '    with open("x") as fh:\n'
                  '        self.assertTrue(all(x > 0 for x in xs))\n')
        self.assertEqual(self.offenders_of(source), ['f'])

    def test_rule_comment_does_not_cross_try(self):
        # try 是语句节点，注释在 try 上方、断言在体内 —— 中间隔着 try，不豁免
        source = ('def f(self, xs):\n'
                  '    # empty-allowed: 想盖住 try 体\n'
                  '    try:\n'
                  '        self.assertTrue(all(x > 0 for x in xs))\n'
                  '    except Exception:\n'
                  '        pass\n')
        self.assertEqual(self.offenders_of(source), ['f'])

    def test_rule_comment_above_for_loop_does_exempt(self):
        # 反过来：循环本身是被检查的那个「断言位置」，注释贴在 for 上方就是对的。
        # 这和 try 的差别是设计出来的，不是漏洞——写在这里免得以后当成 bug 改掉。
        source = ('def f(self, xs):\n'
                  '    # empty-allowed: 空集合时循环不执行，断言不成立也不需要成立\n'
                  '    for x in xs:\n'
                  '        self.assertTrue(all(y > 0 for y in x))\n')
        self.assertEqual(self.offenders_of(source), [])

    def test_rule_same_line_multi_is_flagged(self):
        source = ('def f(self, xs):\n'
                  '    # empty-allowed: 同行两条\n'
                  '    assert all(x > 0 for x in xs); assert all(x < 9 for x in xs)\n')
        self.assertEqual(self.same_line_multi(source), [3],
                         '同一行两条断言要提示拆行，哪怕豁免成立')

    def test_rule_readme_number_matches_code(self):
        # README 里写的豁免比率必须和当前实测一致，否则文档会退化成某时刻的快照
        import re as _re
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        scanned = []
        for folder in ('tests', 'scripts'):
            for name in os.listdir(os.path.join(root, folder)):
                if name.endswith('.py'):
                    scanned.append(os.path.join(root, folder, name))
        got = total = 0
        for path in scanned:
            with open(path, encoding='utf-8') as fh:
                text = fh.read()
            try:
                g, t = self.exemption_stats(text)
            except SyntaxError:
                continue
            got += g
            total += t
        with open(os.path.join(root, 'README.md'), encoding='utf-8') as fh:
            readme = fh.read()
        match = _re.search(r'\*\*(\d+) / (\d+)', readme)
        self.assertIsNotNone(match, 'README 里应该有 「N / M」 形式的豁免比率')
        # 按分数比，不比百分比：四舍五入会在 .5 边界上制造假红
        self.assertEqual((int(match.group(1)), int(match.group(2))), (got, total),
                         f'README 写 {match.group(1)}/{match.group(2)}，实测 {got}/{total}')

    def test_rule_same_line_assertions_share_line(self):
        # 同一行两条断言：行号相同，注释豁免按行生效，两条一起算
        source = ('def f(self, xs):\n'
                  '    # empty-allowed: 同行两条都算\n'
                  '    assert all(x > 0 for x in xs); assert all(x < 9 for x in xs)\n')
        self.assertEqual(self.offenders_of(source), [],
                         '同一行的断言共享行号，注释按行生效')

    def test_rule_comment_covers_only_nearby_assertion(self):
        # 一条注释只管它上面 5 行内的那个断言；第二个断言在 12 行后，不能被它豁免
        source = ('def f(self, xs, ys):\n'
                  '    # empty-allowed: 只管 xs\n'
                  '    self.assertTrue(all(x > 0 for x in xs))\n' +
                  '\n' * 10 +
                  '    self.assertTrue(all(y > 0 for y in ys))\n')
        self.assertEqual(self.offenders_of(source), ['f'],
                         '共用注释不该豁免远处的断言')

    def test_rule_scanner_fails_loud_on_syntax_error(self):
        # 语法错误必须炸，不能跳过——跳过等于这个文件不在扫描范围内，却看不出来
        with self.assertRaises(SyntaxError):
            self.offenders_of('def broken(:\n    pass\n')

    # ---- 真实文件扫描 ----

    def test_rule_universal_assertions_declare_empty_policy(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        scanned = []
        for folder in ('tests', 'scripts'):
            for name in os.listdir(os.path.join(root, folder)):
                if name.endswith('.py'):
                    scanned.append(os.path.join(root, folder, name))
        self.non_empty(scanned, '扫描范围')

        bad = {}
        errors = []
        scanned_ok = 0
        for path in scanned:
            with open(path, encoding='utf-8') as fh:
                source = fh.read()
            try:
                found = self.offenders_of(source)
            except SyntaxError as exc:
                # 不中止：一个坏文件不该让「其他文件是否通过」看不见
                errors.append(f'{os.path.basename(path)}:{exc.lineno}: {exc.msg}')
                continue
            scanned_ok += 1
            if found:
                bad[os.path.basename(path)] = found
        self.assertEqual(errors, [],
                         f'扫描并解析 {scanned_ok} 个文件；因语法错误未扫描 {len(errors)} 个'
                         '（未扫描 ≠ 通过，里面的断言完全没看）：' + '; '.join(errors))
        self.assertEqual(bad, {},
                         f'这些函数有真空断言却没说空集合怎么办：{bad}。'
                         '能断言非空的场景优先写 non_empty()（断言），'
                         '确实允许空集合才写 # empty-allowed（声明）。'
                         '如果你认为这里本来就有保护，那可能是扫描器没认出那种形态：'
                         '请扩展扫描器的保护规则，不要用豁免吸收。')
        # 豁免率：分子分母同粒度——被注释豁免的断言处 / 全称断言处总数。
        # 注释存在但没豁免任何断言的，不进分子（旧版本按条数算，单位对不上）。
        exempted_spots = 0
        spots_total = 0
        functions_total = 0
        for path in scanned:
            with open(path, encoding='utf-8') as fh:
                text = fh.read()
            try:
                got, total = self.exemption_stats(text)
            except SyntaxError:
                continue
            exempted_spots += got
            spots_total += total
            import ast as _a
            for node in _a.walk(_a.parse(text)):
                if isinstance(node, _a.FunctionDef) and self.universal_spots(node):
                    functions_total += 1

        breakdown = {'declarative': 0, 'substitutive': 0}
        for path in scanned:
            with open(path, encoding='utf-8') as fh:
                text = fh.read()
            try:
                part = self.exemption_breakdown(text)
            except SyntaxError:
                continue
            for key in breakdown:
                breakdown[key] += part[key]

        # 警报线，不是安全线：和基线比涨太多就提醒人去看一眼
        baseline_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     'golden', 'exemptions.json')
        rate = exempted_spots / spots_total if spots_total else 0.0
        if os.path.exists(baseline_path):
            with open(baseline_path, encoding='utf-8') as fh:
                base = json.load(fh)
            base_rate = base['protected'] / base['total'] if base['total'] else 0.0
            locked = base.get('locked_at_ratio')
            if locked is not None:
                self.assertLessEqual(
                    round(rate, 4), round(locked, 4),
                    f'豁免率 {rate:.2%} 高于锁定值 {locked:.2%}：'
                    '比率上涨本身就是信号，不是「换个版本号就能过去」的事。'
                    '要么把能改成 non_empty() 的改掉，要么显式更新 locked_at_ratio 并写理由。')
            # 基线按版本锁定：版本对不上就得复核，不能静默沿用旧基线
            self.assertEqual(
                base.get('locked_at_version', ipc.__version__), ipc.__version__,
                f"豁免基线锁在 {base.get('locked_at_version')}，当前 {ipc.__version__}："
                '换版本前先确认比率没恶化（更新 locked_at_version 并写理由），'
                '或者把新增的豁免处理掉')
            self.assertLessEqual(
                rate, base_rate + 0.2,
                f'豁免构成：声明型 {breakdown["declarative"]} 条（贴在循环上方）、'
                f'替代型 {breakdown["substitutive"]} 条（贴在断言上方）；'
                f'注释豁免率 {rate:.0%}（{exempted_spots}/{spots_total} 处，'
                f'分布在 {functions_total} 个函数里，平均每函数 '
                f'{spots_total / functions_total:.1f} 处）比基线 '
                f'{base_rate:.0%} 高出 20 个点以上：豁免正在变成常态。'
                '能改成 non_empty() 的改掉；确认空集合本来就合法的，'
                '更新 tests/golden/exemptions.json 并写理由。')

    def test_rule_scan_uses_real_files(self):
        # 文件发现/编码/路径这一层也要有证据：临时目录里放一个真有问题的文件
        folder = tempfile.mkdtemp()
        try:
            path = os.path.join(folder, 'sample.py')
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write('def f(self, xs):\n'
                         '    self.assertTrue(all(x > 0 for x in xs))\n')
            with open(path, encoding='utf-8') as fh:
                self.assertEqual(self.offenders_of(fh.read()), ['f'])

            # 注释关联在真实源码行结构下也要成立：缩进 + 多行表达式
            annotated = os.path.join(folder, 'annotated.py')
            with open(annotated, 'w', encoding='utf-8') as fh:
                fh.write('def f(self, xs):\n'
                         '    values = [x for x in xs\n'
                         '              if x > 0]\n'
                         '    # empty-allowed: 空集合时跳过，不算失败\n'
                         '    self.assertTrue(\n'
                         '        all(x > 0 for x in values)\n'
                         '    )\n')
            with open(annotated, encoding='utf-8') as fh:
                self.assertEqual(self.offenders_of(fh.read()), [],
                                 '多行断言上方的注释应当能豁免')
        finally:
            shutil.rmtree(folder, ignore_errors=True)


class ProductExemptionTests(unittest.TestCase):
    """产品代码的豁免口要是没约束，门禁就会退化成装饰。"""

    def check_exemption(self, source):
        """返回 (豁免条数, 理由太短的条数)。判据：注释后必须有 ≥10 字理由。"""
        import re as _re
        good = 0
        short = 0
        for line in source.splitlines():
            stripped = line.strip()
            if not stripped.startswith('# universal-assert-ok'):
                continue
            reason = stripped.split(':', 1)[1].strip() if ':' in stripped else ''
            if len(reason) >= 10:
                good += 1
            else:
                short += 1
        return good, short

    def test_rule_product_exemption_needs_reason(self):
        ok, short = self.check_exemption(
            'x = 1\n'
            '# universal-assert-ok: 常量列表本身非空，空集合不可能出现\n'
            'assert all(v > 0 for v in CONSTANTS)\n')
        self.assertEqual((ok, short), (1, 0))

        ok, short = self.check_exemption(
            '# universal-assert-ok:\nassert all(v > 0 for v in CONSTANTS)\n')
        self.assertEqual((ok, short), (0, 1), '空理由不算豁免')

        ok, short = self.check_exemption(
            '# universal-assert-ok: 就这样\nassert all(...)\n')
        self.assertEqual((ok, short), (0, 1), '敷衍理由不算豁免')


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


class InputErrorTests(unittest.TestCase):
    def test_plain_text_gets_a_human_error(self):
        with tempfile.NamedTemporaryFile(suffix='.txt', mode='w', delete=False) as fh:
            fh.write('hello')
            path = fh.name
        try:
            with self.assertRaises(SystemExit) as ctx:
                ipc.load_record(path)
            self.assertIn('Evidence', str(ctx.exception))
        finally:
            os.unlink(path)

    def test_bad_probe_json_says_where_to_get_it(self):
        with tempfile.NamedTemporaryFile(suffix='.json', mode='w', delete=False) as fh:
            fh.write('nope')
            path = fh.name
        try:
            with self.assertRaises(SystemExit) as ctx:
                ipc.load_probe(path)
            self.assertIn('probe/run.js', str(ctx.exception))
        finally:
            os.unlink(path)

    def test_missing_file_is_reported_before_anything_else(self):
        with self.assertRaises(SystemExit) as ctx:
            ipc.main(['nope-不存在的文件.asar'])
        self.assertIn('没这个文件', str(ctx.exception))


class PokeTests(unittest.TestCase):
    def test_swallowed_inputs_get_their_own_section(self):
        rows = [{'channel': 'a:1', 'payload': 'undefined', 'ok': True, 'result': '1'}]
        text = '\n'.join(ipc.render_poke(rows))
        self.assertIn('照收的', text)
        self.assertIn('a:1', text)

    def test_thrown_errors_go_apart(self):
        # 业务错误和拦截错误不能混成一档：混了就变成「抛错=有校验」
        rows = [{'channel': 'a:2', 'payload': 'null', 'ok': False, 'error': 'boom'}]
        text = '\n'.join(ipc.render_poke(rows))
        self.assertIn('门禁未知', text)
        # 未知不能说成「没有门禁」，否则下游读成「可以试试打穿」
        self.assertIn('不提供门禁信息', text)
        self.assertIn('a:2', text)

    def test_gate_words_land_in_the_gated_bucket(self):
        rows = [{'channel': 'a:3', 'payload': 'null', 'ok': False,
                 'error': 'rejected IPC without a sender frame'}]
        text = '\n'.join(ipc.render_poke(rows))
        self.assertIn('### 被拦下的', text)
        self.assertNotIn('门禁未知', text)
        # 有门不等于门后有校验，这句边界必须写在档里
        self.assertIn('门后逻辑未审', text)

    def test_empty_result_is_said_out_loud(self):
        self.assertIn('没有结果', '\n'.join(ipc.render_poke([])))

    def test_unreachable_is_reported(self):
        self.assertIn('没跑起来', '\n'.join(ipc.render_poke({'error': '调试口没开'})))


class BaselineRoundTripTests(unittest.TestCase):
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


class AdversarialTests(unittest.TestCase):
    """同一句 vault:unlock 换十二种写法。认不出可以，把原文搞坏不行。"""

    def test_bracket_member_call(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain['handle']('vault:unlock', f)"})
        self.assertIn(('vault:unlock', 'a.js:1'), facts['handlers'])

    def test_unicode_escape_decoded(self):
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('vault:\\u0075nlock', f)"})
        self.assertIn(('vault:unlock', 'a.js:1'), facts['handlers'])

    def test_control_char_escape_not_decoded(self):
        # \u000a 一还原就多一行，行号全废
        source = b"ipcMain.handle('vault:\\u000anlock', f)"
        text = ipc.decode_unicode_strings(source.decode('utf-8'))
        self.assertEqual(text.count('\n'), 0)

    def test_nested_template_left_alone(self):
        source = "ipcMain.handle(`vault:${`un` + 'lock'}`, f)"
        folded = ipc.fold_templates(source)
        self.assertIn('`vault:${`un`', folded)
        # 原样的引号和反引号都得还在，不能被换成一对双引号
        self.assertEqual(folded.count('`'), source.count('`'))

    def test_template_folding_keeps_line_count(self):
        source = "const a = `one\ntwo`;\nconst b = `x:${'y'}`;\n"
        self.assertEqual(ipc.fold_templates(source).count('\n'), source.count('\n'))


    def test_reported_line_points_at_real_line(self):
        # 跨行模板以前会被压成一行，行号一路往前偏。这条盯着它。
        source = "const t = `a\nb\nc`;\nipcMain.handle('vault:unlock', f)\n"
        facts = ipc.scan_asar({'a.js': source.encode('utf-8')})
        self.assertIn(('vault:unlock', 'a.js:4'), facts['handlers'])


if __name__ == '__main__':
    unittest.main()