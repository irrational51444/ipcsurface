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

    def test_no_window_means_no_sender_claim(self):
        # 只分析了一个文件，没看到窗口代码，就不能断言「没人校验」
        result = minimal_evidence(['a:1'], sender_checks=0)
        result['graph']['nodes'] = []
        facts = ipc.collect_evidence(result)
        texts = [text for _, text, _ in ipc.audit_evidence(facts)]
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
        self.assertEqual(data['schema'], 'ipcsurface/asar/6')
        self.assertIn('limits', data)
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
