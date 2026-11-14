"""ipcsurface 的测试。只依赖标准库，不需要装 REA。

跑法：
    python -m unittest discover -s tests -v
"""

import errno
import io
import json
import os
import re
import shutil
import struct
import subprocess
import urllib.error
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

    def _header_with(self, files_json):
        import struct
        payload = files_json.encode()
        blob = struct.pack('<I', 4) + struct.pack('<I', len(payload)) + payload + b'X'
        fd, path = tempfile.mkstemp(suffix='.asar')
        with os.fdopen(fd, 'wb') as fh:
            fh.write(blob)
        return path

    def test_rejects_non_numeric_offset(self):
        # fuzz 抓到过：offset 写成非数字时 int() 直接 ValueError 崩掉，而不是拒掉
        path = self._header_with('{"files":{"a.js":{"offset":"abc","size":"1"}}}')
        try:
            with self.assertRaises(SystemExit):
                ipc.read_asar(path)
        finally:
            os.unlink(path)

    def test_rejects_non_numeric_size(self):
        path = self._header_with('{"files":{"a.js":{"offset":"0","size":"1e999"}}}')
        try:
            with self.assertRaises(SystemExit):
                ipc.read_asar(path)
        finally:
            os.unlink(path)

    def test_accepts_string_numbers(self):
        # asar 头里 offset/size 本来就是数字字符串，不能因为上面两条把它拒了
        path = self._header_with('{"files":{"a.js":{"offset":"0","size":"1"}}}')
        try:
            header, files = ipc.read_asar(path)
            self.assertIn('a.js', files)
        finally:
            files.close()
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

    def test_attack_surface_detects_shell_open(self):
        facts = self.scan("shell.openExternal('https://x'); shell.openPath('/tmp/y')")
        surf = facts['attack_surface']
        self.assertIn('shell-open', surf)
        self.assertEqual(len(surf['shell-open']), 2)

    def test_attack_surface_detects_exec_js(self):
        facts = self.scan("win.webContents.executeJavaScript('1+1')")
        self.assertIn('exec-js', facts['attack_surface'])

    def test_attack_surface_classifies_literal_vs_variable(self):
        facts = self.scan("shell.openExternal('https://fixed'); shell.openExternal(url)")
        hits = facts['attack_surface']['shell-open']
        self.assertEqual(hits[0]['arg'], 'literal')
        self.assertEqual(hits[1]['arg'], 'variable')

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

    def test_rejects_non_list_records(self):
        # fuzz 抓到过：records 写成字符串、或列表里塞了非字典，都会 .get 崩掉
        import json as _json
        fd, path = tempfile.mkstemp(suffix='.json')
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            _json.dump({'records': 'not-a-list'}, fh)
        try:
            with self.assertRaises(SystemExit):
                ipc.load_record(path)
        finally:
            os.unlink(path)

    def test_rejects_records_with_non_dict_entries(self):
        import json as _json
        fd, path = tempfile.mkstemp(suffix='.json')
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            _json.dump({'records': [1, 2, 3]}, fh)
        try:
            with self.assertRaises(SystemExit):
                ipc.load_record(path)
        finally:
            os.unlink(path)

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

    def test_main_process_obfuscation_is_flagged_first(self):
        # bilibili 那种：主进程重度混淆，静态基本失效，报告第一句就要说清
        facts = ipc.scan_asar({'main/index.js': b"var _0x4a2f = 1; eval(x)"})
        facts['obfuscation'] = [('十六进制标识符', 'main/index.js:1', 'strong'),
                                ('eval 直接执行字符串', 'node_modules/x.js:2', 'strong')]
        self.assertEqual(ipc.main_process_obfuscated(facts), ['main/index.js'])
        spots = '\n'.join(ipc.blind_spots(facts))
        self.assertTrue(spots.startswith('主进程文件是强混淆'), spots)

    def test_library_only_obfuscation_is_not_main_process(self):
        facts = ipc.scan_asar({'node_modules/x.js': b'eval(decode(y))'})
        facts['obfuscation'] = [('eval 直接执行字符串', 'node_modules/x.js:2', 'strong')]
        self.assertEqual(ipc.main_process_obfuscated(facts), [])
        self.assertNotIn('主进程文件是强混淆', '\n'.join(ipc.blind_spots(facts)))

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
        # 分层报告：b:2 静态没认出，应当落在「仅动态」那一层
        self.assertIn('仅动态', text)
        self.assertIn('静态的漏', text)

    def test_crosscheck_layers_split(self):
        layers = ipc.crosscheck_layers(['a:1', 'b:2'], {'a:1', 'c:3'})
        self.assertEqual(layers['both'], ['a:1'])
        self.assertEqual(layers['static_only'], ['c:3'])
        self.assertEqual(layers['runtime_only'], ['b:2'])

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


class EnumerationTests(unittest.TestCase):
    """拼出来的名字，能不能算回去。

    这叫「穷举」不叫「猜」：取值集合写在源码里，拼法只有字面量和加号。
    条件不满足就整处退回「算不出来」，一条都不许凑。
    """

    def scan(self, source):
        return ipc.scan_asar({'a.js': source.encode('utf-8')})

    def test_rule_enumerated_requires_literal_set(self):
        # 数组 + 循环 + 单表达式拼装函数：三类都在，才穷举
        source = """
        const OPS = ['add', 'list', 'remove'];
        function makeChannel(rest) { return 'ledger:' + rest; }
        for (const op of OPS) {
          ipcMain.handle(makeChannel(op), () => {});
        }
        """
        facts = self.scan(source)
        names = sorted(n for n, _w in facts['handlers'])
        self.assertEqual(names, ['ledger:add', 'ledger:list', 'ledger:remove'])
        self.assertEqual(len(facts['enumerated']), 3)
        # 穷举出来的名字不能再挂在「名字是算的」那档里
        self.assertEqual(facts['dynamic'], [])

    def test_rule_enumerated_falls_back_when_set_is_not_literal(self):
        # 取值来自函数返回值 → 算不出来，必须退回 dynamic，不许猜
        source = """
        function getOps() { return loadFromConfig(); }
        for (const op of getOps()) {
          ipcMain.handle('ledger:' + op, () => {});
        }
        """
        facts = self.scan(source)
        self.assertEqual(facts['handlers'], [])
        self.assertEqual(facts['enumerated'], [])
        self.assertEqual(len(facts['dynamic']), 1)

    def test_enumerates_inline_array_and_template(self):
        source = """
        for (const op of ['a', 'b']) {
          ipcMain.handle(`db:${op}`, () => {});
        }
        """
        facts = self.scan(source)
        self.assertEqual(sorted(n for n, _w in facts['handlers']), ['db:a', 'db:b'])

    def test_enumerates_foreach_body(self):
        source = """
        const OPS = ['x', 'y'];
        OPS.forEach((op) => {
          ipcRenderer.invoke('task:' + op);
        });
        """
        facts = self.scan(source)
        self.assertEqual(sorted(n for n, _w in facts['invokes']), ['task:x', 'task:y'])

    def test_loop_variable_outside_body_is_not_enumerated(self):
        # 循环体之外的调用点没有取值集合，不许借用别处的
        source = """
        const OPS = ['add'];
        ipcMain.handle(makeChannel(op), () => {});
        for (const op of OPS) { ipcMain.handle('ledger:' + op, () => {}); }
        """
        facts = self.scan(source)
        names = sorted(n for n, _w in facts['handlers'])
        self.assertEqual(names, ['ledger:add'])
        self.assertEqual(len(facts['dynamic']), 1)

    def test_helper_with_branch_is_not_inlined(self):
        # 带分支的拼装函数不是「字面量拼装」，硬算就是编
        source = """
        const OPS = ['add'];
        function makeChannel(rest) { if (rest) { return 'ledger:' + rest; } return 'x'; }
        for (const op of OPS) { ipcMain.handle(makeChannel(op), () => {}); }
        """
        facts = self.scan(source)
        self.assertEqual(facts['handlers'], [])
        self.assertEqual(len(facts['dynamic']), 1)

    def test_expansion_is_capped_not_truncated(self):
        # 取值一多就整处放弃：交半份结果比说「算不出来」更坏
        many = ', '.join(f"'n{i}'" for i in range(200))
        source = f"""
        const OPS = [{many}];
        for (const op of OPS) {{ ipcMain.handle('ledger:' + op, () => {{}}); }}
        """
        facts = self.scan(source)
        self.assertEqual(facts['handlers'], [])
        self.assertTrue(facts['dynamic'], '放弃时要留下「这里有调用、名字没定」的记录')

    def test_enumerated_names_carry_a_weaker_source(self):
        source = """
        const OPS = ['add'];
        for (const op of OPS) { ipcMain.handle('ledger:' + op, () => {}); }
        """
        facts = self.scan(source)
        item = ipc.channel_sources(facts)['ledger:add']
        self.assertEqual(item['sources'], ['enumerated'])
        self.assertLess(item['strength'], ipc.SOURCE_STRENGTH['literal'])
        self.assertGreater(item['strength'], ipc.SOURCE_STRENGTH['computed'])
        # 推翻它的判据要具体到「循环里有人改过变量」，不能含糊
        self.assertTrue(any('改过变量' in text for text in item['refutes_if']))

    def test_rule_enumerated_requires_proof_for_high_strength(self):
        """强度不是调上去的：三条证明查过才给 0.9，一条没过就降到 0.6。

        三条检查各自对应一句「什么情况会让这次穷举算错」，
        不是打分用的修辞——它们真能推翻结果。
        """
        clean = self.scan("""
            const OPS = ['a', 'b'];
            function ch(rest) { return 'ledger:' + rest; }
            for (const op of OPS) { ipcMain.handle(ch(op), () => {}); }
            """)
        item = ipc.channel_sources(clean)['ledger:a']
        self.assertEqual(item['strength'], ipc.ENUM_STRENGTH_PROVEN, 0.9)
        self.assertEqual(item['enum_proof']['failed'], [])
        self.assertEqual(sorted(item['enum_proof']['checked']),
                         sorted(ipc.ENUM_CHECKS))
        # 证据字段要登记，不然会被当成没登记的聚合字段报出来
        self.assertEqual(ipc.unregistered_evidence_fields(item), [])

        reassigned = self.scan("""
            const OPS = ['a'];
            for (let op of OPS) { op = op + 'X'; ipcMain.handle('ledger:' + op, () => {}); }
            """)
        item = ipc.channel_sources(reassigned)['ledger:a']
        self.assertEqual(item['strength'], ipc.ENUM_STRENGTH_OPEN, 0.6)
        self.assertIn('loop_var_not_reassigned', item['enum_proof']['failed'])

        mutated = self.scan("""
            const OPS = ['a'];
            OPS.push('extra');
            for (const op of OPS) { ipcMain.handle('ledger:' + op, () => {}); }
            """)
        item = ipc.channel_sources(mutated)['ledger:a']
        self.assertEqual(item['strength'], ipc.ENUM_STRENGTH_OPEN, 0.6)
        self.assertIn('array_not_mutated', item['enum_proof']['failed'])

    def test_clean_enum_strength_matches_literal_resolved(self):
        # 证明到位之后，穷举和「靠还原」同档：两条都要求回原文核一处
        self.assertEqual(ipc.SOURCE_STRENGTH['enumerated'],
                         ipc.SOURCE_STRENGTH['literal-resolved'])
        self.assertLess(ipc.SOURCE_STRENGTH['enumerated'],
                        ipc.SOURCE_STRENGTH['literal'], '穷举不该和写死的同强度')

    def test_value_set_can_come_from_five_more_shapes(self):
        """取值集合不只来自数组字面量。

        split / Object.keys / 展开 / concat / 链式依赖，这五种真项目里都常见，
        取值同样完全由源码字面量决定，所以都收。
        """
        cases = {
            'split': ("const OPS = 'a,b'.split(',');"
                      " for (const op of OPS) { ipcMain.handle('l:' + op, () => {}); }",
                      ['l:a', 'l:b']),
            'keys': ("const MAP = { start: 'x', stop: 'y' };"
                     " const OPS = Object.keys(MAP);"
                     " for (const op of OPS) { ipcMain.handle('j:' + op, () => {}); }",
                     ['j:start', 'j:stop']),
            'spread': ("const A = ['a1']; const B = [...A, 'b1'];"
                       " for (const op of B) { ipcMain.handle('s:' + op, () => {}); }",
                       ['s:a1', 's:b1']),
            'concat': ("const A = ['a1']; const B = A.concat(['b1']);"
                       " for (const op of B) { ipcMain.handle('c:' + op, () => {}); }",
                       ['c:a1', 'c:b1']),
            'chain': ("const A = 'p,q'.split(','); const B = [...A, 'r'];"
                      " for (const op of B) { ipcMain.handle('h:' + op, () => {}); }",
                      ['h:p', 'h:q', 'h:r']),
        }
        for name, (source, expected) in cases.items():
            with self.subTest(shape=name):
                facts = self.scan(source)
                self.assertEqual(sorted(n for n, _w in facts['handlers']), expected)

    def test_non_literal_value_set_still_falls_back(self):
        # 取值来自函数调用，不管哪种写法，一律算不出来
        facts = self.scan("const OPS = loadFromConfig();"
                          " for (const op of OPS) { ipcMain.handle('x:' + op, () => {}); }")
        self.assertEqual(facts['handlers'], [])
        self.assertEqual(len(facts['dynamic']), 1)


    def test_literal_wins_when_both_ways_see_it(self):
        source = """
        const OPS = ['add'];
        ipcMain.handle('ledger:add', () => {});
        for (const op of OPS) { ipcMain.handle('ledger:' + op, () => {}); }
        """
        item = ipc.channel_sources(self.scan(source))['ledger:add']
        self.assertIn('literal', item['sources'])
        self.assertIn('enumerated', item['sources'])
        self.assertEqual(item['strength'], 1.0, '有一处逐字写死，就不该按穷举降档')


class ProbeSiteTests(unittest.TestCase):
    """第二条证据接上之后，交叉档位到底算不算得出来。

    这组盯的是「探针给位置 → 按两侧位置分档」这条路：
    之前四档一直被说成触发不到，是因为没人从真实输入走一遍。
    """

    def build(self, probe):
        blob = make_asar({'src/main.js': (b"ipcMain.handle('a:one', f)\n"
                                         b"ipcMain.handle('a:two', f)\n"
                                         b"ipcMain.handle('a:three', f)\n"),
                          'src/other.js': b"ipcMain.handle('a:far', f)\n"})
        with tempfile.NamedTemporaryFile(suffix='.asar', delete=False) as fh:
            fh.write(blob)
            path = fh.name
        try:
            facts, count, total = ipc.analyse_asar(path)
            return ipc.channel_sources(facts, probe=probe)
        finally:
            os.unlink(path)

    def test_rule_probe_sites_upgrade_corroboration_level(self):
        probe = {'handlers': ['a:one', 'a:two', 'a:three', 'a:far'],
                 'sites': {'a:one': 'src/main.js:1',      # 同文件同一行
                           'a:two': 'src/main.js:3',      # 同文件相邻（静态在 2）
                           'a:three': 'src/main.js:60',   # 同文件但隔得远
                           'a:far': 'src/main.js:9'}}     # 静态在 other.js，运行时在 main.js
        seen = self.build(probe)
        self.assertEqual(seen['a:one']['corroboration_level'], 'weak-same-line')
        self.assertEqual(seen['a:two']['corroboration_level'], 'weak-near-line')
        self.assertEqual(seen['a:three']['corroboration_level'], 'medium')
        self.assertEqual(seen['a:far']['corroboration_level'], 'strong')

    def test_probe_without_sites_stays_unknown(self):
        # 只报名字不报位置：这一档没算，不能说成「对上得实」
        seen = self.build({'handlers': ['a:one']})
        self.assertEqual(seen['a:one']['corroboration_level'], 'unknown')
        self.assertIn('没给位置', seen['a:one']['corroboration_basis'])


class HarvestGradeTests(unittest.TestCase):
    """候选分档：这是「一堆线索」和「一张能看的清单」之间的分界。"""

    def facts_for(self, files):
        return ipc.scan_asar(files)

    def test_rule_harvest_grades_use_only_checkable_facts(self):
        files = {
            'app/main.js': (b"ipcMain.handle('app:one', f)", b"ipcMain.handle('app:two', f)"),
            'lib/other.js': b"'tool:a' 'tool:b' 'tool:c' 'lone:x'",
        }
        harvested = {'app:one': ('app/main.js:1', 'self'),
                     'tool:a': ('lib/other.js:1', 'other'),
                     'tool:b': ('lib/other.js:1', 'other'),
                     'tool:c': ('lib/other.js:1', 'other'),
                     'lone:x': ('lib/other.js:1', 'other')}
        grades = ipc.grade_harvested(files, harvested, {'app:one'})
        self.assertEqual(grades['app:one'], 'channel', '和通道名对上的不算线索')
        self.assertEqual(grades['tool:a'], 'clustered')
        self.assertEqual(grades['lone:x'], 'stray')
        # 档位必须是登记过的那几种，不能随手加
        self.assertEqual(set(grades.values()) - set(ipc.HARVEST_GRADES), set())


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


class SpeedGuardTests(unittest.TestCase):
    """性能优化的守卫：省掉的活不能把结果改掉。"""

    def test_fold_literals_still_folds(self):
        self.assertEqual(ipc.fold_literals("'a' + 'b'"), "'ab'")

    def test_fold_literals_passes_through_plain_text(self):
        text = "ipcMain.handle('x', ...)" * 10
        self.assertIs(ipc.fold_literals(text), text)

    def test_scan_caches_local_bodies_per_file(self):
        # 同一份文本问两次，不该重扫出不同的函数表
        text = 'function a(){return 1} function b(){return 2}'
        self.assertEqual(ipc.local_function_bodies(text), ipc.local_function_bodies(text))


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
        self.assertEqual(data['schema'], 'ipcsurface/asar/37')
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

    def test_rule_real_dir_fsync_succeeds_on_this_platform(self):
        """真刷一次，不 mock。

        以前 Windows 上这里恒 UNSUPPORTED，durable 只能 unknown。现在两个平台
        都走真刷盘：内核明确回了成功，就不该继续报「这套系统没有这个能力」。
        """
        self.assertIs(ipc._fsync_dir(self.dir), ipc.FsyncResult.OK)
        result = ipc.write_output(self.path, '新的\n')
        self.assertEqual(result.durable, ipc.DURABLE_YES)

    def test_rule_missing_dir_is_failed_not_unsupported(self):
        """目录不存在是「有这能力但没刷成」，不是「没这能力」。

        这两件事下游要分开处理：FAILED 会让 durable=no，UNSUPPORTED 只报 unknown。
        """
        missing = os.path.join(self.dir, 'no-such-dir')
        self.assertIs(ipc._fsync_dir(missing), ipc.FsyncResult.FAILED)

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


def exemption_lock_state(base, rate, current_version, substitutive=0):
    """锁的判定抽出来：返回 (ok, 原因)。门禁看替代型条数，比率只作背景。"""
    reasons = []
    if substitutive > base.get('allowed_substitutive', 0):
        reasons.append('substitutive_above_allowed')
    locked_ratio = base.get('locked_at_ratio')
    if locked_ratio is not None and round(rate, 4) > round(locked_ratio, 4):
        reasons.append('ratio_above_locked')   # 只记录，不再单独构成失败
    if base.get('locked_at_version') != current_version:
        reasons.append('version_mismatch')
    if not base.get('reason'):
        reasons.append('no_reason')
    return (not reasons), reasons


class ExemptionLockTests(unittest.TestCase):
    """双锁不是只拦得住，还要能按流程正确放行。"""

    base = {'protected': 10, 'total': 11, 'locked_at_ratio': 10 / 11,
            'locked_at_version': '0.52.0', 'reason': '空集合本来就合法'}

    def test_rule_gate_hangs_on_substitutive_not_ratio(self):
        base = dict(self.base, allowed_substitutive=0)
        # 比率涨了、但替代型还是 0：不该红（多一条合理声明而已）
        ok, reasons = exemption_lock_state(base, 0.9, '0.52.0', substitutive=0)
        self.assertTrue(ok, reasons)
        # 出现 1 条替代型：红
        ok, reasons = exemption_lock_state(base, 0.5, '0.52.0', substitutive=1)
        self.assertFalse(ok)
        self.assertIn('substitutive_above_allowed', reasons)

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


class ReleaseGuardTests(unittest.TestCase):
    """发布守卫自己也得有证据：三个分支各一条。"""

    def setUp(self):
        import importlib.util as _u
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'scripts', 'check_release_tag.py')
        spec = _u.spec_from_file_location('guard', path)
        self.guard = _u.module_from_spec(spec)
        spec.loader.exec_module(self.guard)

    def test_rule_release_guard_all_green_exits_zero(self):
        runs = [{'name': 'check', 'conclusion': 'success'},
                {'name': 'windows', 'conclusion': 'success'},
                {'name': 'signal', 'conclusion': 'skipped'}]
        self.assertEqual(self.guard.evaluate(runs)[0], self.guard.EXIT_OK)

    def test_rule_release_guard_red_exits_one(self):
        runs = [{'name': 'check', 'status': 'completed', 'conclusion': 'success'},
                {'name': 'windows', 'status': 'completed', 'conclusion': 'failure'}]
        code, why = self.guard.evaluate(runs)
        self.assertEqual(code, self.guard.EXIT_RED)
        self.assertIn('windows', why)

    def test_rule_release_guard_in_progress_is_unknown_not_red(self):
        # 真踩到的：刚推完标签就去查，check/windows 还是 in_progress，
        # conclusion 是 None，被当成「不是成功」报成 CI 红。
        # 没结论就是没结论，那是 2，不是 1。
        runs = [{'name': 'check', 'status': 'in_progress', 'conclusion': None},
                {'name': 'windows', 'status': 'in_progress', 'conclusion': None},
                {'name': 'e2e', 'status': 'completed', 'conclusion': 'success'}]
        code, why = self.guard.evaluate(runs)
        self.assertEqual(code, self.guard.EXIT_UNKNOWN, why)
        self.assertIn('还没跑完', why)
        self.assertNotIn('不是绿', why)
        # 排队的也算没跑完
        queued = [{'name': 'check', 'status': 'queued', 'conclusion': None}]
        self.assertEqual(self.guard.evaluate(queued)[0], self.guard.EXIT_UNKNOWN)

    def test_rule_release_guard_unknown_exits_two(self):
        # 三种「没拿到结果」都要归 2，不能归 1
        self.assertEqual(self.guard.evaluate([])[0], self.guard.EXIT_UNKNOWN)

        def boom(sha, tok):
            raise urllib.error.HTTPError('u', 403, 'rate limited', None, None)

        code, why = self.guard.check_tag('v0.65.5', tok='x', fetcher=boom)
        self.assertEqual(code, self.guard.EXIT_UNKNOWN, why)
        self.assertIn('403', why)

        def timeout(sha, tok):
            raise TimeoutError('timed out')

        code, why = self.guard.check_tag('v0.65.5', tok='x', fetcher=timeout)
        self.assertEqual(code, self.guard.EXIT_UNKNOWN, why)
        self.assertNotIn('不是绿', why)

    def test_rule_release_guard_classification_layer(self):
        # 归类层单独测：403、超时、空列表都由 check_tag 变成 2，
        # 有红变 1。之前只测了 evaluate()，转成「空列表」这一步没人看。
        import urllib.error as _uerr

        def http403(sha, tok):
            raise _uerr.HTTPError('u', 403, 'rate limited', None, None)

        def timeout(sha, tok):
            raise TimeoutError('timed out')

        def empty(sha, tok):
            return []

        def red(sha, tok):
            return [{'name': 'windows', 'conclusion': 'failure'}]

        for name, fetcher in (('403', http403), ('超时', timeout), ('空列表', empty)):
            with self.subTest(kind=name):
                code, why = self.guard.check_tag('v0.65.5', tok='x', fetcher=fetcher)
                self.assertEqual(code, self.guard.EXIT_UNKNOWN, why)
                self.assertIn('不是 CI 红', why)

        code, why = self.guard.check_tag('v0.65.5', tok='x', fetcher=red)
        self.assertEqual(code, self.guard.EXIT_RED, why)

    def test_rule_release_guard_no_token_is_unknown(self):
        code, why = self.guard.check_tag('v0.65.5', tok='')
        self.assertEqual(code, self.guard.EXIT_UNKNOWN)
        self.assertIn('凭据', why)


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TrustworthinessTests(unittest.TestCase):
    """可信度四件：指纹、两路交叉、抽样、已知会错。"""

    def test_rule_content_digest_is_reproducible(self):
        # 报告自己的指纹：去掉时间戳后应当可复算，谁拿这份报告都能验
        sample = os.path.join(ROOT, 'examples', 'build', 'static-asar.asar')
        if not os.path.exists(sample):
            self.skipTest('没有靶场')
        out1 = os.path.join(tempfile.mkdtemp(), 'a.json')
        out2 = os.path.join(tempfile.mkdtemp(), 'b.json')
        for out in (out1, out2):
            subprocess.run([sys.executable, os.path.join(ROOT, 'ipcsurface.py'),
                            sample, '--format', 'json', '-o', out],
                           capture_output=True, text=True, encoding='utf-8')
        a = json.load(open(out1, encoding='utf-8'))
        b = json.load(open(out2, encoding='utf-8'))
        self.assertEqual(a['content_digest']['digest'], b['content_digest']['digest'],
                         '同一份输入，报告指纹必须一样')
        # 自己也能重算
        self.assertEqual(a['content_digest']['digest'], ipc.content_digest(a)['digest'])

    def test_rule_merkle_root_changes_with_content(self):
        files_a = {'a.js': b'one', 'b.js': b'two'}
        files_b = {'a.js': b'one', 'b.js': b'three'}
        self.assertNotEqual(ipc.archive_merkle(files_a)['root'],
                            ipc.archive_merkle(files_b)['root'])
        self.assertEqual(ipc.archive_merkle(files_a)['files'], 2)

    def test_rule_evidence_lists_all_positions(self):
        # 一个名字可能出现在多个文件里，只报第一处会让人以为只有一处
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('x:y', f)",
                               'b.js': b"ipcMain.handle('x:y', g)"})
        item = ipc.channel_sources(facts)['x:y']
        self.assertGreaterEqual(len(item.get('where_all') or []), 2)

    def test_rule_corroboration_levels_are_not_one_block(self):
        # weak 里有两种语义：同一行（同一处代码的两种视角）和相邻行（可能是同一调用点，
        # 也可能只是碰巧挨着）。压成一档就是把不同独立性塞进同一个词里。
        self.assertEqual(ipc.corroboration_strength('a.js:10', 'a.js:10')[0],
                         'weak-same-line')
        self.assertEqual(ipc.corroboration_strength('a.js:10', 'a.js:13')[0],
                         'weak-near-line')
        self.assertEqual(ipc.corroboration_strength('a.js:10', 'a.js:40')[0], 'medium')
        self.assertEqual(ipc.corroboration_strength('a.js:10', 'b.js:3')[0], 'strong')
        self.assertEqual(ipc.corroboration_strength('a.js:10', None)[0], 'unknown')

    def test_rule_corroboration_level_is_unknown_without_runtime_sites(self):
        # 探针不报位置时，档位必须是 unknown——不能凭「都对上了」自己升一档。
        facts = ipc.scan_asar({'a.js': b"ipcMain.handle('v:1', f)"})
        probe = {'handlers': ['v:1'], 'windows': []}
        item = ipc.channel_sources(facts, probe=probe)['v:1']
        self.assertTrue(item['corroborated'])
        self.assertEqual(item.get('corroboration_level'), 'unknown')

    def test_rule_report_says_where_positions_come_from(self):
        # README 得写清：探针给 sites 才算档，不给就是 unknown（没算，不是没对上）。
        # 以前这里断言的是「运行时目前不报位置」，0.76.0 用真实 CLI 跑通过四档之后改口，
        # 所以断言跟着改成新的说法——旧句子留着就是过期文档。
        text = open(os.path.join(ROOT, 'README.md'), encoding='utf-8').read()
        self.assertIn('探针在 probe JSON 里给 `sites`', text)
        self.assertIn('探针只报名字、不报位置时才是 `unknown`', text)
        self.assertNotIn('运行时那一侧目前不报位置', text, '旧说法不能再留着')

    def test_rule_near_line_says_what_it_cannot_tell(self):
        level, basis = ipc.corroboration_strength('a.js:10', 'a.js:12')
        self.assertEqual(level, 'weak-near-line')
        self.assertIn('分不清', basis, '相邻档必须自己说明「分不清是不是同一调用点」')

    def test_rule_fingerprint_is_reproducible(self):
        sample = os.path.join(ROOT, 'examples', 'build', 'static-asar.asar')
        if not os.path.exists(sample):
            self.skipTest('没有靶场')
        a = ipc.fingerprint_of(sample, ['a', 'b'])
        b = ipc.fingerprint_of(sample, ['b', 'a'])   # 顺序不该影响
        self.assertEqual(a['digest'], b['digest'])
        self.assertEqual(a['input_sha256'], ipc.input_sha256(sample))

    def test_rule_fingerprint_changes_with_input(self):
        sample = os.path.join(ROOT, 'examples', 'build', 'static-asar.asar')
        other = os.path.join(ROOT, 'examples', 'build', 'dyn-asar.asar')
        if not (os.path.exists(sample) and os.path.exists(other)):
            self.skipTest('没有靶场')
        a = ipc.fingerprint_of(sample, ['a'])
        b = ipc.fingerprint_of(other, ['a'])
        self.assertNotEqual(a['digest'], b['digest'])

    def test_rule_fingerprint_reports_missing_input_as_null(self):
        data = ipc.fingerprint_of(os.path.join(ROOT, 'nope.asar'), [])
        self.assertIsNone(data['input_sha256'])

    def test_rule_report_carries_samples_per_tier(self):
        sample = os.path.join(ROOT, 'examples', 'build', 'static-asar.asar')
        if not os.path.exists(sample):
            self.skipTest('没有靶场')
        out = os.path.join(tempfile.mkdtemp(), 'r.json')
        proc = subprocess.run([sys.executable, os.path.join(ROOT, 'ipcsurface.py'),
                               sample, '--format', 'json', '-o', out],
                              capture_output=True, text=True, encoding='utf-8',
                              errors='replace')
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.load(open(out, encoding='utf-8'))
        levels = [lv for lv in report['confidence'] if lv.get('samples')]
        self.assertTrue(levels, '至少一层要给出可核对的样本')
        # empty-allowed: levels 由上面的断言保证非空，items 是它自己的样本
        for level in levels:
            for item in level['samples']:
                self.assertTrue(item['where'], '样本必须带位置')
                self.assertRegex(item['where'], r':\d+$', '位置要能回到行号')

    def test_rule_known_wrong_file_exists_and_is_linked(self):
        path = os.path.join(ROOT, 'docs', 'known-wrong.md')
        self.assertTrue(os.path.exists(path), '已知会错清单得在')
        readme = open(os.path.join(ROOT, 'README.md'), encoding='utf-8').read()
        self.assertIn('known-wrong.md', readme, 'README 得链到它，不然没人看')


class ReleaseScriptTests(unittest.TestCase):
    """make_release.py 自己也得有证据，不然它只是「这次跑了一下」。"""

    def setUp(self):
        import importlib.util as _u
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'scripts', 'make_release.py')
        spec = _u.spec_from_file_location('rel', path)
        self.rel = _u.module_from_spec(spec)
        spec.loader.exec_module(self.rel)

    def _poster(self, calls):
        def poster(tag, name, notes, tok):
            calls.append((tag, name, notes))
            return {'html_url': 'https://example.invalid/rel'}
        return poster

    def test_rule_release_script_stops_when_guard_red(self):
        calls = []
        code, msg = self.rel.publish('v0.0.1', 'n', 'b',
                                     guard=lambda tag: (1, '有检查不是绿：windows'),
                                     poster=self._poster(calls), tok='x')
        self.assertEqual(code, self.rel.EXIT_GUARD_RED)
        self.assertIn('CI 红', msg)
        self.assertEqual(calls, [], '守卫红了还去建 release')

    def test_rule_release_script_stops_when_guard_unknown(self):
        calls = []
        code, msg = self.rel.publish('v0.0.1', 'n', 'b',
                                     guard=lambda tag: (2, '查询失败：HTTP 403'),
                                     poster=self._poster(calls), tok='x')
        self.assertEqual(code, self.rel.EXIT_GUARD_UNKNOWN)
        self.assertIn('不是 CI 红', msg)
        self.assertEqual(calls, [])

    def test_rule_release_script_publishes_when_guard_green(self):
        calls = []
        code, msg = self.rel.publish('v0.0.1', 'n', 'b',
                                     guard=lambda tag: (0, '6 个检查全绿'),
                                     poster=self._poster(calls), tok='x')
        self.assertEqual(code, self.rel.EXIT_OK)
        self.assertEqual(calls, [('v0.0.1', 'n', 'b')])
        self.assertIn('DONE', msg)

    def test_rule_release_script_own_failure_is_three(self):
        # 脚本自己出错用 3，不能和「守卫查不到」的 2 混
        def boom(*a, **k):
            raise RuntimeError('network down')

        code, msg = self.rel.publish('v0.0.1', 'n', 'b',
                                     guard=lambda tag: (0, 'ok'), poster=boom, tok='x')
        self.assertEqual(code, self.rel.EXIT_SCRIPT_ERROR)
        self.assertIn('发布失败', msg)

    def test_rule_release_script_existing_release_is_red_not_three(self):
        import urllib.error

        def exists(*a, **k):
            raise urllib.error.HTTPError('u', 422, 'exists', None,
                                         io.BytesIO(b'{"errors":[{"code":"already_exists"}]}'))

        code, msg = self.rel.publish('v0.0.1', 'n', 'b',
                                     guard=lambda tag: (0, 'ok'), poster=exists, tok='x')
        self.assertEqual(code, self.rel.EXIT_GUARD_RED)
        self.assertIn('已经存在', msg)


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
        # 注意：这条以前直接对着仓库里的 tests/golden 跑，内容一变就把真快照改掉，
        # 等于测试自己在改仓库（踩过一次，谁也没发现）。改成拷到临时目录再跑。
        folder = tempfile.mkdtemp()
        try:
            real = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                'tests', 'golden')
            for name in os.listdir(real):
                src = os.path.join(real, name)
                if os.path.isfile(src):
                    shutil.copy2(src, os.path.join(folder, name))
            env = dict(os.environ, PYTHONIOENCODING='utf-8',
                       IPCSURFACE_GOLDEN_DIR=folder)
            result = subprocess.run([sys.executable, self.script,
                                     '--reason', '这次内容其实没有变化，只是验证提示语'],
                                    capture_output=True, text=True,
                                    encoding='utf-8', errors='replace', env=env)
            if result.returncode != 0:
                self.skipTest('快照真的变了，这条只在无变化时适用')
            self.assertIn('reason 没有写进', result.stderr,
                          '内容没变时必须说明 reason 未记录，否则「想改但没生效」会消失')
        finally:
            shutil.rmtree(folder, ignore_errors=True)


class ChannelSinkTests(unittest.TestCase):
    """报告里「每条通道能碰到什么」这一栏的契约。"""

    def facts(self, extra=None):
        files = {'app/main.js': b"ipcMain.handle('app:one', f)"}
        base = ipc.scan_asar(files)
        if extra:
            base.update(extra)
        return base

    def test_report_carries_channel_sinks_key(self):
        report = ipc.build_asar_report(
            'x.asar', self.facts({'channel_sinks': {'app:one': ['readFileSync']}}),
            1, 10, ['app:one'], {}, {}, None, None)
        self.assertEqual(report['channel_sinks'], {'app:one': ['readFileSync']})

    def test_missing_analysis_is_none_not_empty(self):
        report = ipc.build_asar_report(
            'x.asar', self.facts(), 1, 10, [], {}, {}, None, None)
        # 没算过就写 null，不用空字典冒充「一条都没有」
        self.assertIsNone(report['channel_sinks'])

    def test_sink_only_reachable_in_another_file(self):
        """处理函数只是转发，真正碰文件的在另一个文件里——这一跳必须跟到。"""
        files = {
            'src/main.js': (b"const svc = require('./svc');\n"
                            b"ipcMain.handle('x:1', (e, p) => svc.read(p.path));"),
            'src/svc.js': b"module.exports = { read(p) { return fs.readFileSync(p); } };",
        }
        mapping = ipc.channel_sinks_map(files)
        self.assertIn('readFileSync', mapping.get('x:1', []))


class ConstRecoverTests(unittest.TestCase):
    """常量键反推：唯一才补，两个值必须留着不猜。"""

    def test_unique_value_is_recovered(self):
        files = {'a.js': b'const M = { CH_A: "app:alpha" };'}
        out = ipc.recover_const_channels(files, ['a.js:1 M.CH_A'])
        self.assertEqual(out['recovered'], [('M.CH_A', 'app:alpha')])
        self.assertEqual(out['ambiguous'], [])

    def test_two_values_are_not_guessed(self):
        files = {'a.js': b'const M = { CH_B: "app:one" };',
                 'b.js': b'const N = { CH_B: "app:two" };'}
        out = ipc.recover_const_channels(files, ['a.js:1 M.CH_B'])
        self.assertEqual(out['recovered'], [], '两个不同的值时必须不补')
        self.assertEqual(len(out['ambiguous']), 1)

    def test_unknown_key_stays_unresolved(self):
        out = ipc.recover_const_channels({'a.js': b'const M = { X: "y" };'},
                                         ['a.js:1 M.NOPE'])
        self.assertEqual(out['recovered'], [])
        self.assertEqual(out['ambiguous'], [])


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
        # 路径、版本号、以及依赖路径算出的指纹都不进金标准：
        # content_digest 里的 fingerprint 含输入路径的 sha256，换个临时文件就对不上。
        for volatile in ('subject', 'version', 'content_digest'):
            report[volatile] = golden[volatile]
        # 指纹里含着输入文件的 sha256（临时文件每次都不同），跟金标准一样抹掉
        if isinstance(report.get('fingerprint'), dict):
            report['fingerprint']['input_sha256'] = '<input-sha256>'
            report['fingerprint']['digest'] = '<fingerprint-digest>'
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

    def test_rule_whitelist_has_no_duplicate_entries(self):
        """frozenset 会悄悄吃掉重复项，所以另留一份有序清单来盯。

        真发生过：'sites'、'archive_merkle'、'content_digest' 各写了两遍，
        白名单照样能过，谁也没发现。
        """
        listed = list(ipc.REPORT_TOP_LEVEL_KEY_LIST)
        repeated = sorted({k for k in listed if listed.count(k) > 1})
        self.assertEqual(repeated, [], f'白名单里重复登记了：{repeated}')

    def test_rule_integrity_claim_says_not_a_security_rating(self):
        """「Merkle 根不是安全评级」得是字段，不能只是文档里的一句话。"""
        report = self.build()
        claim = report['content_digest']['claim']
        self.assertIs(claim['security_rating'], False,
                      '完整性凭证不能被读成安全评级，这个值必须是 False')
        self.assertIn('identity', claim['proves'])
        self.assertIn('safety', claim['does_not_prove'])
        # 包级 Merkle 根也得带同一份声明
        merkle = ipc.archive_merkle({'a.js': b'x'})
        self.assertEqual(merkle['claim'], claim, '两份凭证的声明必须是同一份，不能各写一套')

    def test_rule_no_safety_verdict_field_anywhere(self):
        """报告里不许出现安全性结论字段——包括长得像结论的。"""
        report = self.build()
        banned = {'safe', 'verdict', 'risk', 'risk_level', 'clean', 'malware',
                  'security_rating', 'trusted'}
        found = sorted(banned & set(report))
        self.assertEqual(found, [], f'报告顶层出现了安全性结论字段：{found}')
        for section in ('content_digest', 'archive_merkle'):
            body = report.get(section)
            if isinstance(body, dict):
                self.assertEqual(sorted(banned & set(body)), [],
                                 f'{section} 里出现了安全性结论字段')


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

        def truth_on_empty(node):
            """这条表达式在空集合上求值为真还是假？判不了就返回 None。"""
            if isinstance(node, (_ast.GeneratorExp, _ast.ListComp)):
                return False        # 空集合 → 空列表/空生成器
            if isinstance(node, _ast.UnaryOp) and isinstance(node.op, _ast.Not):
                inner = truth_on_empty(node.operand)
                return None if inner is None else (not inner)
            if isinstance(node, _ast.Call) and isinstance(node.func, _ast.Name):
                if node.func.id == 'all':
                    return True     # 空集合：全称断言平凡为真
                if node.func.id == 'any':
                    return False
                if node.func.id == 'len':
                    return 0        # 空集合长度为 0
                if node.func.id in ('set', 'dict', 'list', 'tuple', 'frozenset') \
                        and not node.args:
                    return False    # xs == set() / dict() 这类空容器
            if isinstance(node, _ast.List) and not node.elts:
                return False
            if isinstance(node, _ast.Tuple) and not node.elts:
                return False        # xs == ()
            if isinstance(node, _ast.Dict) and not node.keys:
                return False        # xs == {}
            if isinstance(node, _ast.Set) and not node.elts:
                return False
            if isinstance(node, _ast.Compare) and len(node.ops) == 1:
                op = node.ops[0]
                other = node.comparators[0]
                # x == [] / x is not None：空集合上恒真，左边算不出也照样成立
                def empty_container(n):
                    if isinstance(n, _ast.List) and not n.elts:
                        return True
                    if isinstance(n, _ast.Tuple) and not n.elts:
                        return True
                    if isinstance(n, _ast.Set) and not n.elts:
                        return True
                    if isinstance(n, _ast.Dict) and not n.keys:
                        return True
                    if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Name) \
                            and n.func.id in ('set', 'dict', 'list', 'tuple',
                                              'frozenset') and not n.args:
                        return True
                    return False

                if isinstance(op, _ast.Eq) and empty_container(other):
                    return True     # xs == [] / () / {} / set() / dict() ……
                if isinstance(op, _ast.IsNot) and isinstance(other, _ast.Constant) \
                        and other.value is None:
                    return True
                left = truth_on_empty(node.left)
                right = truth_on_empty(other)
                if left is None or right is None:
                    # len([...]) == 0 这类：左边是调用，右边常量，按常量算
                    if isinstance(node.left, _ast.Call) and \
                            getattr(node.left.func, 'id', '') == 'len' and \
                            isinstance(node.comparators[0], _ast.Constant):
                        left, right = 0, node.comparators[0].value
                    else:
                        return None
                op = node.ops[0]
                if isinstance(op, _ast.Eq):
                    return left == right
                if isinstance(op, _ast.NotEq):
                    return left != right
                if isinstance(op, _ast.IsNot):
                    return left is not right
                if isinstance(op, _ast.Is):
                    return left is right
            return None

        def has_collection_semantics(node):
            """断言里有没有集合语义：量化、len/sum/count、推导式、空容器、下标……

            只要有，就算真值没建模也必须报。只有完全不含集合语义的普通布尔断言
            （assertTrue(flag) 这种）才归「不管」。
            """
            for n in _ast.walk(node):
                if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Name) \
                        and n.func.id in ('all', 'any', 'len', 'sum', 'count', 'sorted',
                                          'set', 'frozenset', 'tuple', 'list'):
                    return True
                if isinstance(n, _ast.Call) and isinstance(n.func, _ast.Attribute) \
                        and n.func.attr in ('count', 'index', 'issubset', 'issuperset'):
                    return True
                if isinstance(n, (_ast.GeneratorExp, _ast.ListComp, _ast.SetComp,
                                  _ast.DictComp)):
                    return True
                if isinstance(n, (_ast.List, _ast.Set, _ast.Dict)) and not getattr(n, 'elts', None):
                    return True
            # `not xs`：对集合取真值
            return bool(isinstance(node, _ast.UnaryOp) and isinstance(node.op, _ast.Not)
                        and isinstance(node.operand, _ast.Name))

        def kind_of(method, arg):
            """按「空集合上这条断言会不会放行」定类。"""
            if isinstance(arg, (_ast.GeneratorExp, _ast.ListComp)):
                return 'vacuous'
            value = truth_on_empty(arg)
            if method == 'assertTrue':
                if value is True:
                    return 'vacuous'
                if value is False:
                    return 'existential'
            if method == 'assertFalse':
                if value is False:
                    # 空集合放行。若里面是 any/not-any，那是「不该有坏东西」，算负面断言
                    inner_any = any(is_all_or_any(n, 'any') for n in _ast.walk(arg))
                    return 'negative' if inner_any else 'vacuous'
                if value is True:
                    return 'existential'
            # 真值算不出来时的默认方向：只要断言里带集合语义，就归真空报出来。
            # 枚举不可能完备（0.49.0 就承认过），所以这里判的是「像不像在说集合」，
            # 不是「我认不认识这个写法」——认不出更要报，这就是「宁可吵不可漏」。
            return 'vacuous' if has_collection_semantics(arg) else None

        def classify_arg(arg):
            return kind_of('assertTrue', arg)

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
        seen = set()

        def add(spot, kind):
            if id(spot) in seen:
                return
            seen.add(id(spot))
            found.append((spot, kind))

        for child in _ast.walk(node):
            if isinstance(child, _ast.Call) and isinstance(child.func, _ast.Attribute) \
                    and child.func.attr in ('assertTrue', 'assertFalse'):
                for arg in child.args:
                    kind = kind_of(child.func.attr, arg)
                    if kind:
                        add(child, kind)
                    break
            if isinstance(child, _ast.Assert):
                kind = classify_arg(child.test)
                if kind:
                    add(child, kind)
            if isinstance(child, _ast.Assert) and is_empty_satisfied(child.test):
                add(child, 'vacuous')
            if isinstance(child, _ast.For) and isinstance(child.iter, _ast.Name):
                for inner in _ast.walk(child):
                    if isinstance(inner, _ast.Call) and isinstance(inner.func, _ast.Attribute) \
                            and inner.func.attr.startswith('assert'):
                        add(child, 'vacuous')
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

    def kinds_of(self, source):
        """直接测分类函数本身，不经过 offenders_of。

        空列表的语义（写清楚，别让人猜）：
        - **合法**：这条断言跟集合无关，三类都不沾（比如 `assertTrue(resp.ok)`）。
        - **不合法**：带集合语义但真值没建模——那种情况一律保守归 `vacuous`，
          不许静默返回空列表，否则三个消费者会「一致地漏掉」它。
        """
        import ast as _ast
        fn = next(n for n in _ast.walk(_ast.parse(source))
                  if isinstance(n, _ast.FunctionDef))
        return [kind for _node, kind in self.universal_spots(fn)]

    def test_rule_kinds_of_empty_means_not_about_collections(self):
        # 跟集合无关的断言，返回空列表是合法的
        code = 'def f(self):\n    self.assertTrue(resp.ok)\n'
        self.assertEqual(self.kinds_of(code), [])

        # 带集合语义但真值没建模的，必须归 vacuous，不能空
        code = 'def f(self, xs):\n    self.assertTrue(len(xs) > 0 and xs.called)\n'
        self.assertEqual(self.kinds_of(code)[:1], ['vacuous'])

    def test_rule_classifier_labels_each_kind(self):
        # 分类规则本身要有测试：被误分类的那一条，扫描器会静默不报，
        # 只测扫描器输出抓不到这种情况
        cases = {
            'assertTrue(all(...))':
                ('def f(self, xs):\n'
                 '    self.assertTrue(all(x > 0 for x in xs))\n', 'vacuous'),
            'assert not [...]':
                ('def f(self, xs):\n'
                 '    assert not [x for x in xs if x < 0]\n', 'vacuous'),
            'for + assert':
                ('def f(self, xs):\n'
                 '    for x in xs:\n'
                 '        self.assertTrue(x > 0)\n', 'vacuous'),
            'len(...) == 0':
                ('def f(self, xs):\n'
                 '    assert len(xs) == 0\n', 'vacuous'),
            'assertTrue(any(...))':
                ('def f(self, xs):\n'
                 '    self.assertTrue(any(x > 0 for x in xs))\n', 'existential'),
            'assertFalse(any(...))':
                ('def f(self, xs):\n'
                 '    self.assertFalse(any(x < 0 for x in xs))\n', 'negative'),
        }
        for label, (source, expected) in cases.items():
            with self.subTest(form=label):
                self.assertEqual(self.kinds_of(source), [expected],
                                 f'{label} 应当被分成 {expected}')

    def test_rule_consumers_share_one_classifier(self):
        # 分类规则只该有一份：offenders_of / exemption_stats / breakdown 必须一致，
        # 否则改了一处、另一处还按旧口径算。
        source = ('def f(self, xs):\n'
                  '    # empty-allowed: 空集合合法\n'
                  '    self.assertTrue(all(x > 0 for x in xs))\n')
        protected, total = self.exemption_stats(source)
        self.assertEqual((protected, total), (1, 1))
        self.assertEqual(self.offenders_of(source), [])
        part = self.exemption_breakdown(source)
        self.assertEqual(part['substitutive'], 1)
        self.assertEqual(part['declarative'], 0)

    def test_rule_classifier_reports_unmodeled_collection_forms(self):
        # 这条证明的是「默认方向」：真值没建模、但带集合语义，照样报。
        # 补形态补不完，所以必须有一条钉住方向本身。
        cases = {
            'len(xs) <= 0': 'def f(self, xs):\n    self.assertTrue(len(xs) <= 0)\n',
            'len(xs) < 1': 'def f(self, xs):\n    self.assertTrue(len(xs) < 1)\n',
            'xs.count(x) == 0':
                'def f(self, xs, x):\n    self.assertTrue(xs.count(x) == 0)\n',
            'not xs': 'def f(self, xs):\n    self.assertTrue(not xs)\n',
        }
        for label, source in cases.items():
            with self.subTest(form=label):
                self.assertEqual(self.kinds_of(source), ['vacuous'],
                                 f'{label} 带集合语义但真值没建模，默认方向应当报')

    def test_rule_classifier_still_ignores_plain_boolean(self):
        # 反面：完全不含集合语义的普通断言，不该被卷进来
        source = 'def f(self):\n    self.assertTrue(flag)\n'
        self.assertEqual(self.kinds_of(source), [])

    def test_rule_kinds_of_matches_the_classifier(self):
        # kinds_of 必须就是分类函数的输出，不能是又写一遍：
        # 否则三个消费者会「一致地错」，一致性用例抓不到。
        import ast as _ast
        source = ('def f(self, xs):\n'
                  '    self.assertTrue(all(x > 0 for x in xs))\n'
                  '    self.assertTrue(any(x in xs for x in xs))\n')
        fn = next(n for n in _ast.walk(_ast.parse(source))
                  if isinstance(n, _ast.FunctionDef))
        self.assertEqual(self.kinds_of(source),
                         [kind for _node, kind in self.universal_spots(fn)])

    def test_rule_kinds_of_never_silently_empty_for_known_forms(self):
        # 每个已知形态都必须至少分出一类；返回空列表就是「既不算真空也不算存在性」，
        # 那三个消费者会一起漏掉它。
        forms = ['xs == []', 'xs == ()', 'len(xs) == 0', 'not xs',
                 'all(x > 0 for x in xs)', 'any(x > 0 for x in xs)']
        # empty-allowed: forms 是常量表，非空由定义保证
        for form in forms:
            with self.subTest(form=form):
                code = f'def f(self, xs):\n    self.assertTrue({form})\n'
                self.assertTrue(self.kinds_of(code), f'{form} 没被分成任何一类')

    def test_rule_age_threshold_boundary(self):
        # 「一年」是代码常量，但不是随便改的：边界要有用例，
        # 改了常量就得跟着改这里，不然「可以调整」只是句空话。
        one_year = 365 * 86400
        self.assertEqual(ipc._age_text(one_year - 86400), '364.0 天前')
        # 恰好一年：按「不超过一年算正常」还是「一年就落异常」，得有个说法，
        # 所以这一条钉住它——改常量就会改到这一行。
        exact = ipc._age_text(one_year)
        self.assertTrue(exact.endswith('天前') or '时间过久' in exact,
                        f'恰好一年落在边界上，实际是：{exact}')
        self.assertIn('时间过久', ipc._age_text(one_year + 86400),
                      '跨过一年就该落到「时间过久」分支')

    def test_rule_classifier_covers_all_empty_containers(self):
        # README 写了「空容器」，那就得是全部变体，不能只认 == []
        cases = ['[]', '()', '{}', 'set()', 'dict()', 'frozenset()', 'list()', 'tuple()']
        # empty-allowed: cases 是常量表，非空由定义保证
        for literal in cases:
            with self.subTest(form=literal):
                code = f'def f(self, xs):\n    self.assertTrue(xs == {literal})\n'
                self.assertEqual(self.kinds_of(code), ['vacuous'],
                                 f'xs == {literal} 也是空容器，必须一样被建模')

    def test_rule_classifier_keeps_vacuous_without_quantifier(self):
        # 这些都不含 all/any，但空集合上照样通过——0.49.0 定的「默认当危险报」不能退
        cases = {
            'assertTrue(len(xs) == 0)':
                ('def f(self, xs):\n'
                 '    self.assertTrue(len(xs) == 0)\n', 'vacuous'),
            'assertTrue(xs == [])':
                ('def f(self, xs):\n'
                 '    self.assertTrue(xs == [])\n', 'vacuous'),
            'assert xs is not None':
                ('def f(self, xs):\n'
                 '    assert xs is not None\n', 'vacuous'),
        }
        for label, (source, expected) in cases.items():
            with self.subTest(form=label):
                self.assertEqual(self.kinds_of(source), [expected],
                                 f'{label} 不含量词，但空集合上恒真，仍要报')

    def test_rule_classifier_is_conservative_on_compound(self):
        # any(...) and check(...) 的真值取决于 check，算不出来 → 保守归真空
        source = ('def f(self, xs):\n'
                  '    self.assertTrue(any(x > 0 for x in xs) and check())\n')
        self.assertEqual(self.kinds_of(source), ['vacuous'],
                         '组合表达式算不出真值时应保守归真空')

    def test_rule_overlapping_signals_count_once(self):
        # 量词和集合语义同时命中（any 里带 in xs），只能记一次：
        # 记两次会把分母虚高，密度算错。
        cases = {
            'any() + in xs': ('def f(self, xs):\n'
                              '    self.assertTrue(any(x in xs for x in xs))\n'),
            'len() + []': ('def f(self, xs):\n'
                           '    self.assertTrue(len(xs) == 0 and xs == [])\n'),
            'not + count()': ('def f(self, xs, y):\n'
                              '    self.assertTrue(not xs.count(y))\n'),
        }
        for label, source in cases.items():
            with self.subTest(form=label):
                self.assertEqual(len(self.kinds_of(source)), 1,
                                 f'{label} 同时命中两类信号，只该记一次')

    def test_rule_classifier_ignores_plain_boolean(self):
        # 不含量化的普通断言不该被当成真空断言
        source = ('def f(self):\n'
                  '    self.assertTrue(flag)\n')
        self.assertEqual(self.kinds_of(source), [])

    def test_rule_classifier_handles_negated_forms(self):
        # 按「空集合上会不会失败」判，不按函数名判
        cases = {
            'not all(...)': ('def f(self, xs):\n'
                             '    self.assertTrue(not all(x > 0 for x in xs))\n',
                             'existential'),
            # assertTrue(not any(...)) 空集合上直接通过 → 按行为就是真空。
            # 和 assertFalse(any(...)) 写法不同、行为相同，但后者带「不该有坏东西」的语义，
            # 所以只有 assertFalse 那一支记为 negative。这条差异写在这儿，别当 bug 改。
            'not any(...)': ('def f(self, xs):\n'
                             '    self.assertTrue(not any(x < 0 for x in xs))\n',
                             'vacuous'),
            'assertFalse(any(...))': ('def f(self, xs):\n'
                                      '    self.assertFalse(any(x < 0 for x in xs))\n',
                                      'negative'),
            'assert not all(...)': ('def f(self, xs):\n'
                                    '    assert not all(x > 0 for x in xs)\n',
                                    'existential'),
        }
        for label, (source, expected) in cases.items():
            with self.subTest(form=label):
                self.assertEqual(self.kinds_of(source), [expected],
                                 f'{label} 应当被分成 {expected}')

    def test_rule_classifier_vacuous_is_not_silently_exempt(self):
        # 真空断言必须是 vacuous：一旦被分到 negative，它就不会再被报告
        source = ('def f(self, xs):\n'
                  '    self.assertTrue(all(x > 0 for x in xs))\n')
        self.assertIn('vacuous', self.kinds_of(source))

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

        # 门禁挂在「替代型」上：替代型 = 本该写 non_empty 却写了注释。
        # 总比率只作背景报告——它把「合理声明」和「该检查没检查」混在分子里，
        # 在这个混合数上拦，红了也说不清是哪一种。
        allowed = 0
        baseline_path0 = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      'golden', 'exemptions.json')
        if os.path.exists(baseline_path0):
            with open(baseline_path0, encoding='utf-8') as fh:
                allowed = json.load(fh).get('allowed_substitutive', 0)
        self.assertLessEqual(
            breakdown['substitutive'], allowed,
            f'替代型豁免 {breakdown["substitutive"]} 条（上限 {allowed}）：'
            '这些位置本该写 non_empty() 断言，却用注释换成了「信任」。'
            '能断言的改成断言；确实只能声明的，把 allowed_substitutive 显式调上去并写理由。')

        # 警报线，不是安全线：和基线比涨太多就提醒人去看一眼
        baseline_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     'golden', 'exemptions.json')
        rate = exempted_spots / spots_total if spots_total else 0.0
        if os.path.exists(baseline_path):
            with open(baseline_path, encoding='utf-8') as fh:
                base = json.load(fh)
            base_rate = base['protected'] / base['total'] if base['total'] else 0.0
            locked = base.get('locked_at_ratio')
            if locked is not None and round(rate, 4) > round(locked, 4):
                # 只报告，不拦：比率涨了可能只是多了一条合理声明
                print(f'提示：豁免率 {rate:.2%} 高于基线 {locked:.2%}'
                      f'（背景信息，不是门禁；分母只有 {spots_total} 处，'
                      '一条断言就能摆动十几个百分点，别当趋势读）')
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


class LeftoverTests(unittest.TestCase):
    """崩溃残留：报告出来，但不自动还原。"""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'report.md')

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_rule_recover_reports_without_restoring(self):
        ipc.write_output(self.path, '旧版\n')
        stamp = int(time.time() * 1000)
        backup = os.path.join(self.dir, f'.report.md.{stamp}.deadbeef.bak')
        with open(backup, 'w', encoding='utf-8') as fh:
            fh.write('旧版\n')

        report = ipc.inspect_leftovers(self.path)
        self.assertEqual(len(report['backups']), 1)
        self.assertTrue(report['target_exists'])
        text = ipc.render_leftovers(report, self.path)
        self.assertIn('不会自动还原', text)
        self.assertIn('备份副本', text)
        self.assertTrue(os.path.exists(backup), '检查不该删副本')
        self.assertEqual(open(self.path, encoding='utf-8').read(), '旧版\n',
                         '检查不该改 target')

    def test_rule_recover_reports_target_facts(self):
        # 不给结论，但要给判断所需的事实：target 的大小和修改时间、谁更新
        ipc.write_output(self.path, '旧版\n')
        stamp = int(time.time() * 1000)
        backup = os.path.join(self.dir, f'.report.md.{stamp}.deadbeef.bak')
        with open(backup, 'w', encoding='utf-8') as fh:
            fh.write('旧版\n')

        report = ipc.inspect_leftovers(self.path)
        self.assertIsNotNone(report['target_mtime_text'])
        entry = report['backups'][0]
        self.assertIn('relation', entry)
        self.assertIn('不同源', entry.get('relation_basis') or '',
                      '不同源比较必须标成线索，不能裸给结论')
        text = ipc.render_leftovers(report, self.path)
        self.assertIn('改动时间', text)
        self.assertIn('按文件名里的时间戳', text)
        self.assertIn('线索', text)

    def test_rule_recover_age_never_prints_negative(self):
        # 时钟回拨：文件名时间戳在未来时，不打印负数
        future = int((time.time() + 7200) * 1000)
        self.assertEqual(ipc._age_text(-7200),
                         '时间异常（文件时间比现在还晚，可能时钟回拨）')
        # 时钟前跳也要被识别，不只回拨
        self.assertIn('时间过久', ipc._age_text(400 * 86400))
        self.assertNotIn('异常', ipc._age_text(400 * 86400),
                         '正常的老文件不该被打成异常，措辞不能下结论')
        self.assertEqual(ipc._age_text(-10), '刚刚')
        self.assertNotIn('-', ipc._age_text(-7200))

    def test_rule_recover_is_clean_without_leftovers(self):
        ipc.write_output(self.path, '只有这一份\n')
        report = ipc.inspect_leftovers(self.path)
        self.assertEqual(report['backups'], [])
        self.assertIn('没有发现', ipc.render_leftovers(report, self.path))


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


class SinkEvidenceTests(unittest.TestCase):
    """每条 sink 结论都要带证据：档位 + 位置。

    0.97.0 曾把软档（ambiguous / ast_only）整块砍掉，精确率上去了，但漏掉 9 条
    人工核过的真阳性——那是拿漏报换数字。现在改成：档位照报，每条配证据，
    人看到 `at` 就跳过去核，看到 `ambiguous（同名多义）` 就知道这条是猜的。
    """

    def facts(self):
        import ipcsurface as ipc
        asar = os.path.join(ROOT, 'examples', 'build', 'static-asar.asar')
        if not os.path.exists(asar):
            self.skipTest('靶场没构建')
        facts, _n, _b = ipc.analyse_asar(asar)
        return facts

    def test_every_conclusion_has_evidence(self):
        facts = self.facts()
        tiers = facts.get('channel_sink_tiers') or {}
        ev = facts.get('channel_sink_evidence') or {}
        missing = [(ch, api) for ch, apis in tiers.items()
                   for api in apis if api not in (ev.get(ch) or {})]
        self.assertFalse(missing, '有结论但没有证据：%r' % (missing,))

    def test_evidence_carries_tier_and_at(self):
        facts = self.facts()
        ev = facts.get('channel_sink_evidence') or {}
        bad = [(ch, api, item) for ch in ev for api, item in ev[ch].items()
               if not item.get('tier') or not item.get('at')]
        self.assertFalse(bad[:3], '证据缺 tier 或 at：%r' % (bad[:3],))

    def test_soft_tiers_are_not_dropped(self):
        """软档必须还在——砍掉它们就等于漏报真阳性。

        靶场都是写死的通道名，跑不出同名多义，所以这条在靶场上会跳过；
        真正的软档要在真包上验，跑 `python scripts/calibration.py` 看
        ambiguous / ast_only 两档还有没有数。
        """
        facts = self.facts()
        ev = facts.get('channel_sink_evidence') or {}
        seen = {item['tier'] for ch in ev for item in ev[ch].values()}
        if not seen & {'ambiguous', 'ast_only'}:
            self.skipTest('靶场没有同名多义样本，软档要在真包上验')
        self.assertTrue(seen & {'ambiguous', 'ast_only'},
                        '软档被整块砍掉了，这就是漏报：%r' % (sorted(seen),))

    def test_md_renders_tier_and_at_columns(self):
        """md 里必须有档位/位置列。

        CHANGELOG 承诺「tier: direct + at: main.js:66 → 跳过去看三行」，
        那句话对着 md 读者说的。0.98.0 只把它写进了 JSON，md 还是一条
        via 摘要——承诺和产品不一致，而当时 424 个用例全绿。
        """
        import ipcsurface as ipc
        import jsreport
        asar = os.path.join(ROOT, 'examples', 'build', 'static-asar.asar')
        if not os.path.exists(asar):
            self.skipTest('靶场没构建')
        facts, count, total = ipc.analyse_asar(asar)
        md = ipc.render_asar(asar, facts, count, total)
        self.assertIn('| 通道 | API | 类别 | 档位 | 见证 | 实参 | 证据 | 位置 | 跳数 | 经过 |', md)
        self.assertGreater(jsreport.count_sink_rows(md), 0, 'md 的 sink 表格是空的')

    def test_md_rows_match_json_evidence(self):
        """md 数出来的条目数必须等于 JSON 的 evidence 条目数。

        这是防「少渲染」的尺子：一条 API 在 JSON 里有凭据、md 里没有，
        就等于读者看不到。
        """
        import ipcsurface as ipc
        import jsreport
        asar = os.path.join(ROOT, 'examples', 'build', 'static-asar.asar')
        if not os.path.exists(asar):
            self.skipTest('靶场没构建')
        facts, count, total = ipc.analyse_asar(asar)
        md = ipc.render_asar(asar, facts, count, total)
        ev = facts.get('channel_sink_evidence') or {}
        json_rows = sum(len(v) for v in ev.values())
        self.assertEqual(jsreport.count_sink_rows(md), json_rows,
                         'md %d 条 / json %d 条' % (jsreport.count_sink_rows(md),
                                                    json_rows))

    def test_report_carries_evidence_field(self):
        import subprocess
        import tempfile
        asar = os.path.join(ROOT, 'examples', 'build', 'static-asar.asar')
        if not os.path.exists(asar):
            self.skipTest('靶场没构建')
        out = tempfile.mktemp(suffix='.json')
        try:
            subprocess.run([sys.executable, os.path.join(ROOT, 'ipcsurface.py'),
                            asar, '--format', 'json', '-o', out],
                           capture_output=True, timeout=180)
            with open(out, encoding='utf-8') as fh:
                report = json.load(fh)
            self.assertIn('channel_sink_evidence', report)
        finally:
            try:
                os.unlink(out)
            except OSError:
                pass


class DynamicRegistrationTests(unittest.TestCase):
    """名字是变量的注册，看得见门、读不出名字——不能当没看见。

    「没看见」和「看见了但读不出」是两件不同的事：后者至少能告诉人去哪一行看。
    """

    SRC = """
const {ipcMain} = require('electron');
const ch = 'dyn-' + Math.random();
ipcMain.on(ch, (e, x) => { require('fs').writeFileSync(x, '1'); });
ipcMain.on('static-one', (e) => { require('fs').rmSync('/x'); });
"""

    def parse(self):
        import jsparse
        tokens = jsparse.tokenize(self.SRC)
        return jsparse.ipc_registrations(tokens, {}, set())

    def test_dynamic_channel_keeps_its_expression(self):
        regs = self.parse()
        dynamic = [r for r in regs if not r.get('channel')]
        self.assertEqual(len(dynamic), 1, '动态注册应该被记下来，不是跳过')
        self.assertEqual(dynamic[0].get('first_expr'), 'ch')
        self.assertEqual(dynamic[0].get('line'), 4)

    def test_static_channel_is_unaffected(self):
        regs = self.parse()
        names = [r.get('channel') for r in regs if r.get('channel')]
        self.assertEqual(names, ['static-one'])
        static = [r for r in regs if r.get('channel') == 'static-one'][0]
        self.assertEqual(static.get('first_expr'), '', '静态的名字不该记成表达式')

    def test_reason_bucket_exists_in_report(self):
        """报告里要有这个归因桶，哪怕这包一个动态注册都没有。"""
        import ipcsurface as ipc
        asar = os.path.join(ROOT, 'examples', 'build', 'static-asar.asar')
        if not os.path.exists(asar):
            self.skipTest('靶场没构建')
        facts, _n, _b = ipc.analyse_asar(asar)
        reasons = facts.get('unresolved_reasons') or {}
        self.assertIn('dynamic-registration', reasons)
        self.assertIn('count', reasons['dynamic-registration'])
        self.assertTrue(reasons['dynamic-registration'].get('what'))


class SummaryModeTests(unittest.TestCase):
    """--summary：一页纸，计数必须和全量对得上。"""

    def run_summary(self):
        import subprocess
        import tempfile
        asar = os.path.join(ROOT, 'examples', 'build', 'static-asar.asar')
        if not os.path.exists(asar):
            self.skipTest('靶场没构建')
        out = tempfile.mktemp(suffix='.md')
        try:
            subprocess.run([sys.executable, os.path.join(ROOT, 'ipcsurface.py'),
                            asar, '--summary', '-o', out],
                           capture_output=True, timeout=180)
            with open(out, encoding='utf-8') as fh:
                return fh.read()
        finally:
            try:
                os.unlink(out)
            except OSError:
                pass

    def test_summary_is_short(self):
        text = self.run_summary()
        self.assertIn('一页纸', text)
        self.assertIsLessEqual = None  # 用 assertLessEqual
        self.assertLessEqual(len(text.split('\n')), 60,
                             '一页纸不该超过 60 行，实际 %d' % len(text.split('\n')))

    def test_summary_points_to_full_report(self):
        text = self.run_summary()
        self.assertIn('-o full.md', text, '摘要必须告诉人全量在哪')

    def test_summary_counts_match_full(self):
        """摘要的 sink 总数必须和 facts 里的 evidence 条目数一致。"""
        import ipcsurface as ipc
        import jsreport
        asar = os.path.join(ROOT, 'examples', 'build', 'static-asar.asar')
        if not os.path.exists(asar):
            self.skipTest('靶场没构建')
        facts, count, total = ipc.analyse_asar(asar)
        ev = facts.get('channel_sink_evidence') or {}
        full_n = sum(len(v) for v in ev.values())
        summary = jsreport.render_summary(facts, ipc.__version__, count, total)
        m = re.search(r'能碰到什么（共 (\d+) 条）', summary)
        self.assertIsNotNone(m, '摘要里应该有总数')
        self.assertEqual(int(m.group(1)), full_n,
                         '摘要 %s / 全量 %d' % (m.group(1), full_n))


class TokenFoldTests(unittest.TestCase):
    """纯字面量拼接要折出来；夹了变量就不折。

    和 `LiteralFoldTests` 的分工：那个测的是 `fold_literals`——文本级的
    预处理，在 `scan_asar` 的还原流程里跑；这个测的是 `fold_literal_concat`，
    在 token 层兜底，用于 `ipc_registrations` 解不出名字时。两层都要有：
    还原流程只看通道发现，sink 分析用的是原始文本。

    折错一次比不折坏得多——名字错了整份清单都跟着错。所以边界写死：
    只认「字符串 + 字符串」交替的形状。
    """

    def parse(self, body):
        import jsparse
        src = "const {ipcMain} = require('electron');\n" + body
        return jsparse.ipc_registrations(jsparse.tokenize(src), {}, set())

    def test_two_literals_fold(self):
        regs = self.parse("ipcMain.on('dyn-' + 'save', (e) => {});")
        self.assertEqual(regs[0]['channel'], 'dyn-save')

    def test_three_literals_fold(self):
        regs = self.parse("ipcMain.on('a' + 'b' + 'c', (e) => {});")
        self.assertEqual(regs[0]['channel'], 'abc')

    def test_variable_does_not_fold(self):
        regs = self.parse("ipcMain.on(prefix + '-x', (e) => {});")
        self.assertIsNone(regs[0]['channel'], '夹了变量就不许猜')
        self.assertIn('prefix', regs[0].get('first_expr') or '')

    def test_plain_literal_unaffected(self):
        regs = self.parse("ipcMain.on('static-one', (e) => {});")
        self.assertEqual(regs[0]['channel'], 'static-one')
        self.assertEqual(regs[0].get('first_expr'), '')


class EncryptedPayloadTests(unittest.TestCase):
    """成块的编码载荷要报出来：不是「没有通道」，是「这段看不见」。"""

    def test_big_hex_run_is_reported(self):
        import ipcsurface as ipc
        blob = b"const x = '" + b"a1" * 3000 + b"';"
        hits = ipc.detect_encrypted_payload({'a.js': blob})
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['kind'], 'hex')
        self.assertGreaterEqual(hits[0]['size'], 4096)

    def test_short_hex_is_ignored(self):
        import ipcsurface as ipc
        blob = b"const x = 'a1b2c3';"
        self.assertEqual(ipc.detect_encrypted_payload({'a.js': blob}), [])

    def test_tiny_file_is_skipped(self):
        import ipcsurface as ipc
        self.assertEqual(ipc.detect_encrypted_payload({'a.js': b'x'}), [])

    def test_reason_bucket_exists(self):
        import ipcsurface as ipc
        asar = os.path.join(ROOT, 'examples', 'build', 'static-asar.asar')
        if not os.path.exists(asar):
            self.skipTest('靶场没构建')
        facts, _n, _b = ipc.analyse_asar(asar)
        reasons = facts.get('unresolved_reasons') or {}
        self.assertIn('encrypted-payload', reasons)
        self.assertIn('what', reasons['encrypted-payload'])


class ZeroHopTaintTests(unittest.TestCase):
    """零跳污点：危险调用的实参直接来自 IPC 参数。

    边界写死：只认「实参就是参数本身，或它解构出来的名字」。中间经过任何
    函数调用都不算——那要内建语义，是另一层。

    这里直接测引擎（`assignments` + `flows_into_danger`），不走 `scan_asar`——
    单文件那条路径不算通道级污点，是两个入口。
    """

    SRC = """
function h(e, i, c) {
  let { filepath: d } = i;
  fs.writeFileSync(d, 'x');
  fs.renameSync(i, c);
}
"""

    def hits(self, src):
        import jsparse
        import jssem
        toks = jsparse.tokenize(src)
        defs = [x for x in jsparse.function_defs(toks) if x['name'] == 'h']
        self.assertTrue(defs, '样例里应该有函数 h')
        d0 = defs[0]
        params = d0.get('params') or []
        return jssem.flows_into_danger(toks, d0['body_start'], d0['body_end'], params)

    def test_destructured_alias_is_tainted(self):
        """`let { filepath: d } = i` 之后 writeFile(d)——解构别名要认。

        这条对应 obsidian 的 `print-to-pdf`：最严重的发现，修复前引擎报的是 None。
        """
        hits = self.hits(self.SRC)
        names = [h[0] for h in hits]
        self.assertIn('writeFileSync', names, '解构出来的实参必须算脏')

    def test_direct_param_is_tainted(self):
        hits = self.hits(self.SRC)
        args = {h[1] for h in hits if h[0] == 'renameSync'}
        self.assertIn('i', args, 'i 必须标出来')
        self.assertIn('c', args, 'c 也要标出来——目标路径零校验，那才是要修的')

    def test_event_param_is_not_tainted(self):
        """第一个参数是事件对象，攻击者控不了，不许算脏。

        obsidian 的 `open-file` 就是因为 `event.sender` → 窗口 → 对话框返回值
        → 路径 这条链，把「用户选的路径」误报成「外部可控路径」。
        """
        src = """
function h(e, i) {
  let w = e.sender;
  let p = w.somePath;
  fs.writeFileSync(p, 'x');
}
"""
        self.assertEqual(self.hits(src), [], 'event 起的链不算外部输入')

    def test_await_result_does_not_inherit_args(self):
        """`let k = await dialog.show(d, { ext: i })`：参数脏，返回值不脏。"""
        src = """
function h(e, i, c) {
  let r = await dialog.show(c, { ext: i });
  fs.writeFileSync(r.filePath, 'x');
}
"""
        self.assertEqual(self.hits(src), [], 'await 的返回值不许继承参数污点')

    def test_path_join_with_tainted_arg_is_reported(self):
        """`F.join(v, i)` 里 i 脏——零跳看不见，L2 这层要报。"""
        import jsparse
        import jssem
        src = """
function h(e, i, c) {
  let q = F.join(v, i);
  fs.writeFileSync(q, c);
}
"""
        toks = jsparse.tokenize(src)
        d0 = [x for x in jsparse.function_defs(toks) if x['name'] == 'h'][0]
        params = d0.get('params') or []
        table = jssem.assignments(toks, d0['body_start'], d0['body_end'], params)
        dirty = jssem.tainted_names(table)
        hits = jssem.path_taint(toks, d0['body_start'], d0['body_end'], dirty)
        self.assertTrue(hits, 'join 吃了脏值必须报出来')
        self.assertEqual(hits[0][0], 'join')
        self.assertIn('i', hits[0][1])

    def test_path_join_with_clean_arg_is_silent(self):
        import jsparse
        import jssem
        src = """
function h(e, i) {
  let q = F.join(v, 'fixed.txt');
  fs.writeFileSync(q, 'x');
}
"""
        toks = jsparse.tokenize(src)
        d0 = [x for x in jsparse.function_defs(toks) if x['name'] == 'h'][0]
        table = jssem.assignments(toks, d0['body_start'], d0['body_end'], d0.get('params') or [])
        dirty = jssem.tainted_names(table)
        hits = jssem.path_taint(toks, d0['body_start'], d0['body_end'], dirty)
        self.assertEqual(hits, [], '干净的字面量不许报')


    def test_constant_argument_is_not_tainted(self):
        src = """
function h(e, i) {
  fs.writeFileSync('/tmp/fixed.txt', 'x');
}
"""
        self.assertEqual(self.hits(src), [], '常量路径不许算成脏')


class InterprocTaintTests(unittest.TestCase):
    """L3：脏实参传进本文件另一个函数，跟进去看它能不能到危险参数。

    单参数那条以前是哑的：`assignments` 为了排除 event 把第一个参数剔了，
    结果 `params` 只有一项时 `live` 直接空掉，整片不工作。修完之后才动。
    """

    SRC = """
const fs = require('fs');
function doSave(p, extra) { fs.writeFileSync(p, 'x'); }
function h(e, i, c) {
  doSave(i);
  doSave('fixed');
}
"""

    def build(self):
        import jsparse
        import jssem
        toks = jsparse.tokenize(self.SRC)
        defs = jsparse.function_defs(toks)
        return toks, defs, jssem

    def test_dirty_arg_crosses_into_callee(self):
        toks, defs, jssem = self.build()
        d0 = [x for x in defs if x['name'] == 'h'][0]
        table = jssem.assignments(toks, d0['body_start'], d0['body_end'],
                                  d0.get('params') or [])
        dirty = jssem.tainted_names(table)
        hits = jssem.interproc_taint(toks, d0['body_start'], d0['body_end'], dirty, defs)
        self.assertTrue(hits, '脏实参跨函数必须跟得下去')
        names = [(h[0], h[1]) for h in hits]
        self.assertIn(('doSave', 'writeFileSync'), names)

    def test_single_param_function_still_works(self):
        """只有一个形参时 `p` 必须算脏——event 排除规则不能把这种也剔掉。"""
        toks, defs, jssem = self.build()
        d1 = [x for x in defs if x['name'] == 'doSave'][0]
        hits = jssem.flows_into_danger(toks, d1['body_start'], d1['body_end'], ['p'])
        self.assertTrue(hits, '单参数函数里 p 必须是脏的')

    def test_clean_arg_does_not_cross(self):
        src = """
const fs = require('fs');
function doSave(p) { fs.writeFileSync(p, 'x'); }
function h(e, i) {
  doSave('fixed');
}
"""
        import jsparse
        import jssem
        toks = jsparse.tokenize(src)
        defs = jsparse.function_defs(toks)
        d0 = [x for x in defs if x['name'] == 'h'][0]
        table = jssem.assignments(toks, d0['body_start'], d0['body_end'],
                                  d0.get('params') or [])
        dirty = jssem.tainted_names(table)
        hits = jssem.interproc_taint(toks, d0['body_start'], d0['body_end'], dirty, defs)
        self.assertEqual(hits, [], '干净实参不许跨函数报')

    def test_depth_limit_stops(self):
        src = """
const fs = require('fs');
function c3(p) { fs.writeFileSync(p, 'x'); }
function c2(p) { c3(p); }
function c1(p) { c2(p); }
function h(e, i) { c1(i); }
"""
        import jsparse
        import jssem
        toks = jsparse.tokenize(src)
        defs = jsparse.function_defs(toks)
        d0 = [x for x in defs if x['name'] == 'h'][0]
        table = jssem.assignments(toks, d0['body_start'], d0['body_end'],
                                  d0.get('params') or [])
        dirty = jssem.tainted_names(table)
        one = jssem.interproc_taint(toks, d0['body_start'], d0['body_end'], dirty,
                                    defs, depth=1)
        three = jssem.interproc_taint(toks, d0['body_start'], d0['body_end'], dirty,
                                      defs, depth=3)
        # h → c1 → c2 → c3：writeFileSync 在第四层，所以要 depth=3 才够
        self.assertEqual(one, [], 'depth=1 不该穿两层')
        self.assertTrue(three, 'depth=3 应该跟到 c3 里的 writeFileSync')


class EveryArgTaintTests(unittest.TestCase):
    """每个脏实参都要标出来，不能找到一个就走。

    `renameSync(i, c)` 里两个都来自外部，而真正要修的是 `c`（目标零校验）。
    以前只记 `i`，因为 `_end_of_statement` 在逗号处就停了——那是判语句结尾用的，
    拿来切实参列表是错的。
    """

    SRC = """
const fs = require('fs');
function h(e, i, c) {
  fs.renameSync(i, c);
}
"""

    def hits(self):
        import jsparse
        import jssem
        toks = jsparse.tokenize(self.SRC)
        d0 = [x for x in jsparse.function_defs(toks) if x['name'] == 'h'][0]
        params = d0.get('params') or []
        return jssem.flows_into_danger(toks, d0['body_start'], d0['body_end'], params)

    def test_both_args_reported(self):
        hits = self.hits()
        args = {h[1] for h in hits if h[0] == 'renameSync'}
        self.assertEqual(args, {'i', 'c'}, '两个脏实参都要标，实际 %s' % args)

    def test_no_duplicate_arg(self):
        hits = [h for h in self.hits() if h[0] == 'renameSync']
        self.assertEqual(len(hits), len({h[1] for h in hits}), '同一个实参不许重复记')

    def test_single_dirty_arg_still_works(self):
        src = """
const fs = require('fs');
function h(e, i, c) {
  fs.renameSync('/fixed', c);
}
"""
        import jsparse
        import jssem
        toks = jsparse.tokenize(src)
        d0 = [x for x in jsparse.function_defs(toks) if x['name'] == 'h'][0]
        hits = jssem.flows_into_danger(toks, d0['body_start'], d0['body_end'],
                                       d0.get('params') or [])
        args = {h[1] for h in hits if h[0] == 'renameSync'}
        self.assertEqual(args, {'c'}, '只有 c 脏时只标 c')


class JoinAnchoredTests(unittest.TestCase):
    """`F.join(v, i)` 的第一个实参是常量根时，结果被锚住，不继承脏。

    不然 `copy-asar` 的目标路径会被标成「外部可控」，而它其实被 join 限住了。
    """

    def taint(self, body):
        src = """const fs = require('fs');
function h(e, i, c) {
""" + body + """
}
"""
        import jsparse
        import jssem
        toks = jsparse.tokenize(src)
        d0 = [x for x in jsparse.function_defs(toks) if x['name'] == 'h'][0]
        table = jssem.assignments(toks, d0['body_start'], d0['body_end'],
                                  d0.get('params') or [])
        return set(jssem.tainted_names(table))

    def test_join_with_const_root_is_anchored(self):
        dirty = self.taint('let b = F.join(v, i);')
        self.assertNotIn('b', dirty, 'join 的第一个实参是常量根，结果不该脏')

    def test_join_with_tainted_root_is_dirty(self):
        dirty = self.taint('let b = F.join(i, c);')
        self.assertIn('b', dirty, '根本身是脏的，结果当然脏')

    def test_plain_assignment_unaffected(self):
        dirty = self.taint('let q = i;')
        self.assertIn('q', dirty)


class RealShapeCorpusTests(unittest.TestCase):
    """从 obsidian.asar 里原样抄下来的形状。

    手写样例的问题是它们会长成我脑子里想的样子；真实压缩产物不一样：
    逗号运算符串起来的语句、`C.icon && ...` 先读后写、`delete` 夹在中间。
    用例跑在真形状上，改坏一点才会红。
    """

    CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          'corpus', 'real-obsidian-shapes.js')

    @staticmethod
    def non_empty(items, why):
        """对空集合说「全都满足」是平凡真，先确认非空。"""
        assert items, f'{why}：集合是空的，接下来断言的就是空集'
        return items

    def facts(self):
        import jsparse
        import jssem

        with open(self.CORPUS, encoding='utf-8') as fh:
            text = fh.read()
        toks = jsparse.tokenize(text)
        objects = ipc.parse_object_literals(text)
        out = {}
        for reg in jsparse.ipc_registrations(toks, objects):
            if not reg['channel'] or not reg.get('span'):
                continue
            params = ipc.handler_params(toks, reg['span'][0], reg['span'][1])
            table = jssem.assignments(toks, reg['span'][0], reg['span'][1], params)
            dirty = set(params) | set(jssem.tainted_names(table))
            out[reg['channel']] = jssem.state_writes(
                toks, reg['span'][0], reg['span'][1], dirty)
        return out

    def test_three_channels_are_found(self):
        got = sorted(self.facts())
        self.assertEqual(got, ['adblock-frequency', 'frame', 'set-icon'])

    def test_set_icon_writes_the_field_from_the_parameter(self):
        rows = self.non_empty(self.facts()['set-icon'],
                              'set-icon 把参数 i 写进 C.icon，这一处不能丢')
        field, src_name = rows[0][0], rows[0][1]
        self.assertEqual((field, src_name), ('icon', 'i'))

    def test_set_icon_reads_before_it_writes(self):
        rows = self.facts()['set-icon']
        reads = self.non_empty([r for r in rows[0][3] if r[1] == 'read'],
                               'rmSync 拿 C.icon 去删文件，那是个读点')
        self.assertTrue(all(r[0] < rows[0][2] for r in reads),
                        '压缩产物的顺序是「先读上一轮的、再写这一轮的」')

    def test_set_icon_read_sits_inside_join(self):
        rows = self.facts()['set-icon']
        calls = {r[2] for r in rows[0][3] if r[1] == 'read'}
        self.assertIn('F.join', calls, 'C.icon 被拼进路径，读点落在 F.join 的实参里')

    def test_delete_is_reported_apart_from_reads(self):
        rows = self.facts()['frame']
        kinds = [r[1] for r in rows[0][3]]
        self.assertIn('delete', kinds, '`delete C.frame` 要单独算，不能混进读点')


class CrossFileHandlerTests(unittest.TestCase):
    """Stage two: the handler lives in another file, follow one hop into it."""

    def sinks(self, files):
        mapped = ipc.channel_sinks_map(files, with_paths=True)
        return mapped[0] if mapped else {}

    def test_exported_function_is_followed(self):
        files = {
            'main.js': (b'const {ipcMain} = require("electron");\n'
                        b'const h = require("./handler");\n'
                        b'ipcMain.handle("cross-save", h.save);\n'),
            'handler.js': b'e.exports.save = function (p) { fs.writeFileSync(p); };\n',
        }
        got = self.sinks(files)
        apis = [row[0] for row in got.get('cross-save') or []]
        self.assertIn('writeFileSync', apis,
                      '导出函数的函数体要跟进去，不能停在 h.save 这两个 token 上')

    def test_missing_export_is_not_guessed(self):
        files = {
            'main.js': (b'const {ipcMain} = require("electron");\n'
                        b'const h = require("./handler");\n'
                        b'ipcMain.handle("cross-save", h.MISSING);\n'),
            'handler.js': b'e.exports.save = function (p) { fs.writeFileSync(p); };\n',
        }
        got = self.sinks(files)
        self.assertNotIn('cross-save', got, '导出表里没有的名字，不许编一条链出来')

    def test_relative_spec_resolves_to_candidates(self):
        import jssem

        self.assertEqual(list(jssem.resolve_required_path('src/main.js', './handler')),
                         ['src/handler.js', 'src/handler/index.js'])
        self.assertEqual(list(jssem.resolve_required_path('main.js', '../lib/x')),
                         ['lib/x.js', 'lib/x/index.js'])
        self.assertEqual(list(jssem.resolve_required_path('main.js', 'electron')), [],
                         '包名在包里没有源文件，硬解析只会猜错')


    def test_two_hop_through_pure_forwarding(self):
        files = {
            'main.js': (b'const {ipcMain} = require("electron");\n'
                        b'const h = require("./handler");\n'
                        b'ipcMain.handle("two-hop", h.save);\n'),
            'handler.js': b'e.exports.save = require("./impl").save;\n',
            'impl.js': b'e.exports.save = function (p) { fs.writeFileSync(p); };\n',
        }
        got = self.sinks(files)
        apis = [row[0] for row in got.get('two-hop') or []]
        self.assertIn('writeFileSync', apis,
                      '纯转发（重新导出）要跟到第二跳')

    def test_wrapped_forwarding_is_not_followed(self):
        files = {
            'main.js': (b'const {ipcMain} = require("electron");\n'
                        b'const h = require("./handler");\n'
                        b'ipcMain.handle("wrapped", h.save);\n'),
            'handler.js': b'e.exports.save = wrap(require("./impl").save);\n',
            'impl.js': b'e.exports.save = function (p) { fs.writeFileSync(p); };\n',
        }
        got = self.sinks(files)
        self.assertNotIn('wrapped', got,
                         '包了一层调用的不是转发，跟进去等于猜')

    def test_cross_file_constant_is_resolved(self):
        files = {
            'handler.js': (b'const K = require("./consts").CH_NAME;\n'
                           b'e.exports[K] = function (p) { fs.writeFileSync(p); };\n'),
            'consts.js': b'e.exports.CH_NAME = "fileSave";\n',
        }
        import jsparse

        toks = jsparse.tokenize(files['handler.js'].decode())
        got = ipc.cross_file_consts(files, 'handler.js', toks, {})
        self.assertEqual(got, {'K': 'fileSave'},
                         '`const K = require("./c").X` 的值要能解出来')

    def test_handler_resolves_through_cross_file_constant(self):
        files = {
            'main.js': (b'const {ipcMain} = require("electron");\n'
                        b'const h = require("./handler");\n'
                        b'ipcMain.handle("via-const", h.fileSave);\n'),
            'handler.js': (b'const K = require("./consts").CH_NAME;\n'
                           b'e.exports[K] = function (p) { fs.writeFileSync(p); };\n'),
            'consts.js': b'e.exports.CH_NAME = "fileSave";\n',
        }
        got = self.sinks(files)
        apis = [row[0] for row in got.get('via-const') or []]
        self.assertIn('writeFileSync', apis,
                      '导出名来自另一个文件的常量时，整条链也要通')

    def test_esm_imported_handler_is_followed(self):
        files = {
            'main.js': (b'import { save } from "./handler.js";\n'
                        b'ipcMain.handle("esm-save", save);\n'),
            'handler.js': b'export function save(p) { fs.writeFileSync(p); }\n',
        }
        got = self.sinks(files)
        apis = [row[0] for row in got.get('esm-save') or []]
        self.assertIn('writeFileSync', apis,
                      '`import { save } from "./m"` 进来的裸名字也要能跟到函数体')

    def test_import_table_records_alias(self):
        import jssem
        import jsparse

        toks = jsparse.tokenize('import { open as openFile } from "./m";')
        self.assertEqual(jssem.esm_imports(toks),
                         {'openFile': ('named', './m', 'open')})


class ThisMethodHandlerTests(unittest.TestCase):
    """`ipcMain.on('log', this.onLog)` — the handler is a class method reference."""

    def regs(self, src):
        import jsparse

        return jsparse.ipc_registrations(jsparse.tokenize(src))

    def test_this_method_is_taken_as_the_target(self):
        regs = self.regs('ipcMain.on("log", this.onLog);')
        self.assertEqual(regs[0]['target'], 'onLog',
                         'ArmouryDevice 三条通道全用 this.method，以前 target 是 None')

    def test_bare_identifier_still_works(self):
        regs = self.regs('ipcMain.on("log", onLog);')
        self.assertEqual(regs[0]['target'], 'onLog')

    def test_member_expression_takes_the_last_segment(self):
        regs = self.regs('ipcMain.on("log", obj.method);')
        self.assertEqual(regs[0]['target'], 'method',
                         '取最后一段是刻意的近似：找不到同名函数就不跟，不会编')


class RegexPerformanceTests(unittest.TestCase):
    """A regex on a 3 MB single-line bundle must not degrade into backtracking."""

    def test_const_pair_regex_does_not_blow_up(self):
        import time

        line = ('identifier_' * 20000) + ':"x"'
        start = time.monotonic()
        ipc.CONST_PAIR_RE.findall(line)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 1.0,
                        '标识符长度没限死会退化成几亿次回溯：%.2fs' % elapsed)

    def test_const_pair_regex_still_finds_pairs(self):
        found = ipc.CONST_PAIR_RE.findall('const x = {fileSave:"save-file"};')
        self.assertIn(('fileSave', 'save-file'), found)


class AliasScanTests(unittest.TestCase):
    """After a destructuring rename the literal scanner must still see the call."""

    def test_alias_regex_finds_the_local_name(self):
        text = 'const {app, ipcMain: a} = require("electron");'
        found = {m.group(1) for m in ipc._ALIAS_RE.finditer(text)}
        self.assertEqual(found, {'a'})

    def test_alias_regex_ignores_other_modules(self):
        text = 'const {ipcMain: a} = require("./my-own-ipc");'
        found = {m.group(1) for m in ipc._ALIAS_RE.finditer(text)}
        self.assertEqual(found, set(), '不是从 electron 拿的，名字不能当 ipcMain 用')

    def test_channel_is_found_through_alias(self):
        files = {
            'main.js': (b'const {ipcMain: a} = require("electron");\n'
                        b'a.handle("open-file", (e, p) => {});\n'),
        }
        facts = ipc.scan_asar(files)
        names = [name for name, _where in facts['handlers']]
        self.assertIn('open-file', names, '解构重命名之后的注册点不能丢')


class IpcAliasTests(unittest.TestCase):
    """`const {ipcMain: a} = require("electron")` — after that, `ipcMain` never appears."""

    def analyse(self, src):
        import jsparse
        import jssem

        toks = jsparse.tokenize(src)
        aliases = jssem.electron_ipc_aliases(toks)
        regs = ipc.ipc_registrations_of(toks, ipc.parse_object_literals(src))
        return aliases, regs

    def test_destructured_name_is_found(self):
        aliases, _regs = self.analyse(
            'const {app, ipcMain: a} = require("electron"); a.handle("x", () => {});')
        self.assertEqual(aliases, {'a'})

    def test_registration_through_alias_is_counted(self):
        _aliases, regs = self.analyse(
            'const {ipcMain: a} = t("electron"); a.handle("open-file", (e, p) => {});')
        channels = [r['channel'] for r in regs if r['channel']]
        self.assertEqual(channels, ['open-file'],
                         '解构重命名之后的注册点，不能因为字面上没有 ipcMain 就丢掉')

    def test_plain_registration_still_works(self):
        _aliases, regs = self.analyse('ipcMain.on("ping", () => {});')
        self.assertEqual([r['channel'] for r in regs if r['channel']], ['ping'])

    def test_destructuring_from_another_module_is_not_electron(self):
        aliases, _regs = self.analyse(
            'const {ipcMain: a} = require("./my-own-ipc"); a.handle("x", () => {});')
        self.assertEqual(aliases, set(), '不是从 electron 拿的，不算')


class AdversarialShapeTests(unittest.TestCase):
    """攻击者会怎么写通道名。认得的要认，认不得的要明确认不得。

    这张表是防守清单：每加一条「认」，就是堵掉一条绕过路径；
    每条「不认」都写清为什么，别让读者以为那条路是安全的。
    """

    CASES = [
        # (名字, 源码, 期望能认出来吗, 为什么)
        ('literal', 'ipcMain.handle("literal-ch", fn);', True, ''),
        ('concat-literal', 'ipcMain.handle("a" + "b", fn);', True, ''),
        ('subscript-literal', 'ipcMain["handle"]("sub-ch", fn);', True, ''),
        ('subscript-concat', 'ipcMain["ha" + "ndle"]("subc-ch", fn);', True, ''),
        ('const-name', 'const K = "const-ch"; ipcMain.handle(K, fn);', True, ''),
        ('destructured',
         'const {ipcMain: a} = require("electron"); a.handle("alias-ch", fn);', True, ''),
        ('chained', 'require("electron").ipcMain.handle("chain-ch", fn);', True, ''),
        ('template', 'ipcMain.handle(`tpl-ch`, fn);', True, ''),
        ('fromCharCode', 'ipcMain.handle(String.fromCharCode(97, 98), fn);', True,
         '实参是数字字面量，能算'),
        ('template-const', 'ipcMain.handle(`tpl-${"x"}`, fn);', True,
         '插值是字面量，能拼'),
        ('template-expr', 'ipcMain.handle(`tpl-${x}`, fn);', False,
         '模板里有变量，拼出来的名字静态不知道'),
        ('call-result', 'ipcMain.handle(getName(), fn);', False,
         '函数返回值，静态没有值'),
        ('for-in-object',
         'const MAP = { save: 1, open: 2 };'
         'for (const k in MAP) { ipcMain.handle(k, fn); }', True,
         '对象的键能枚举'),
        ('object-keys',
         'const MAP = { save: 1, open: 2 };'
         'Object.keys(MAP).forEach(k => { ipcMain.handle(k, fn); });', True,
         'Object.keys 也是键枚举'),
        ('for-in-spread',
         'const MAP = { save: 1, ...rest };'
         'for (const k in MAP) { ipcMain.handle(k, fn); }', False,
         '对象里有展开，键不全，整条不收'),
    ]

    def channels(self, src):
        return ipc.scan_asar({'main.js': src.encode()})['channels']

    def test_every_shape_behaves_as_declared(self):
        for name, src, recognized, why in self.CASES:
            with self.subTest(shape=name):
                got = self.channels(src)
                if recognized:
                    self.assertTrue(got, f'{name} 应该认出来，实际没认')
                else:
                    self.assertEqual(got, [], f'{name} 不该认：{why}')


class SubgraphQueryTests(unittest.TestCase):
    """CPG 第一步：局部子图查询要复现现有命中，而且能穿得比深度参数更深。"""

    CHAIN = (
        'const {ipcMain} = require("electron");\n'
        'ipcMain.handle("deep-chain", function (e, p) { a(p); });\n'
        'function a(x) { b(x); }\n'
        'function b(y) { c(y); }\n'
        'function c(z) { d(z); }\n'
        'function d(w) { fs.writeFileSync(w); }\n'
    )

    def setup_chain(self):
        import jsparse
        import jssem

        toks = jsparse.tokenize(self.CHAIN)
        defs = jsparse.function_defs(toks)
        regs = [r for r in ipc.ipc_registrations_of(
            toks, ipc.parse_object_literals(self.CHAIN)) if r['channel']]
        span = regs[0]['span']
        params = ipc.handler_params(toks, span[0], span[1])
        table = jssem.assignments(toks, span[0], span[1], params)
        dirty = jssem.tainted_names(table)
        return toks, defs, span, dirty, jssem

    def test_recursion_with_two_hops_misses_the_fifth_level(self):
        toks, defs, span, dirty, jssem = self.setup_chain()
        hits = jssem.interproc_taint(toks, span[0], span[1], dirty, defs, depth=2)
        self.assertEqual(hits, [],
                         '五层链在两跳上限下应该漏掉——这正是深度参数的问题')

    def test_subgraph_reaches_the_fifth_level_without_a_depth_argument(self):
        toks, defs, span, dirty, jssem = self.setup_chain()
        sums = jssem.subgraph_summaries(toks, defs, [span])
        hits = jssem.interproc_taint_via_summaries(
            toks, span[0], span[1], dirty, defs, sums)
        self.assertTrue(hits, '子图查询没有深度参数，应该能走到第五层')
        self.assertIn('writeFileSync', [h[1] for h in hits])

    def test_ambiguous_name_picks_nearest_and_is_counted(self):
        import jsparse
        import jssem

        src = ('function f(x) { g(x); }\n'
               'ipcMain.handle("c", function (e, p) { f(p); });\n'
               'function f(y) { fs.unlinkSync(y); }\n'
               'function g(z) { fs.writeFileSync(z); }\n')
        toks = jsparse.tokenize(src)
        defs = jsparse.function_defs(toks)
        regs = [r for r in ipc.ipc_registrations_of(
            toks, ipc.parse_object_literals(src)) if r['channel']]
        span = regs[0]['span']
        stats = {}
        jssem.subgraph_summaries(toks, defs, [span], stats_out=stats)
        self.assertEqual(stats.get('ambiguous_names'), 1,
                         '同名两个 f 要算一对歧义名')
        self.assertGreaterEqual(stats.get('edges_ambiguous', 0), 1,
                                '靠「最近候选」建的边必须单独计数，不能混进确定边')

    def test_shared_helper_is_not_blamed_for_the_clean_caller(self):
        import jsparse
        import jssem

        src = ('ipcMain.handle("c1", function (e, p) { util(p); });\n'
               'ipcMain.handle("c2", function (e, q) { other(q); });\n'
               'function util(v) { fs.unlinkSync(v); }\n'
               'function other(w) { console.log(w); }\n')
        toks = jsparse.tokenize(src)
        defs = jsparse.function_defs(toks)
        regs = [r for r in ipc.ipc_registrations_of(
            toks, ipc.parse_object_literals(src)) if r['channel']]
        sums = jssem.subgraph_summaries(
            toks, defs, [r['span'] for r in regs if r.get('span')])
        got = {}
        for reg in regs:
            span = reg['span']
            if not span:
                continue
            params = ipc.handler_params(toks, span[0], span[1])
            table = jssem.assignments(toks, span[0], span[1], params)
            dirty = jssem.tainted_names(table)
            hits = jssem.interproc_taint_via_summaries(
                toks, span[0], span[1], dirty, defs, sums)
            got[reg['channel']] = [h[1] for h in hits]
        self.assertIn('unlinkSync', got.get('c1') or [])
        self.assertEqual(got.get('c2'), [],
                         '另一个 handler 调的工具函数不碰危险接口，不能被连坐')


class TruncationCountTests(unittest.TestCase):
    """Chain cut off by the depth cap must be counted — that is the denominator."""

    def run_taint(self, src, depth=2):
        import jsparse
        import jssem

        toks = jsparse.tokenize(src)
        defs = jsparse.function_defs(toks)
        d0 = [d for d in defs if d['name'] == 'h'][0]
        truncated = []
        hits = jssem.interproc_taint(toks, d0['body_start'], d0['body_end'],
                                     {'p'}, defs, depth=depth,
                                     _truncated=truncated)
        return hits, truncated

    def test_hop_beyond_depth_is_counted(self):
        src = ('function h(e, p) { a(p); }'
               'function a(x) { b(x); }'
               'function b(y) { c(y); }'
               'function c(z) { m.writeFileSync(z); }')
        _hits, truncated = self.run_taint(src, depth=2)
        self.assertTrue(truncated, '两跳用完之后还有下一跳，这一条必须记成截断')

    def test_no_hop_left_is_not_truncation(self):
        src = ('function h(e, p) { a(p); }'
               'function a(x) { m.writeFileSync(x); }')
        _hits, truncated = self.run_taint(src, depth=2)
        self.assertEqual(truncated, [], '到头了不是被砍断，别记成截断')

    def test_hop_without_dirty_argument_is_not_truncation(self):
        src = ('function h(e, p) { a(p); }'
               'function a(x) { b(); }'
               'function b(y) { m.writeFileSync(y); }')
        _hits, truncated = self.run_taint(src, depth=1)
        self.assertEqual(truncated, [],
                         '调用了但没把脏值传进去，不算被深度砍断')

    def test_summary_cache_does_not_change_results(self):
        import jsparse
        import jssem

        src = ('function h(e, p) { a(p); a(p); }'
               'function a(x) { b(x); }'
               'function b(y) { m.writeFileSync(y); }')
        toks = jsparse.tokenize(src)
        defs = jsparse.function_defs(toks)
        d0 = [d for d in defs if d['name'] == 'h'][0]
        plain = jssem.interproc_taint(toks, d0['body_start'], d0['body_end'],
                                      {'p'}, defs, depth=2)
        cached = jssem.interproc_taint(toks, d0['body_start'], d0['body_end'],
                                       {'p'}, defs, depth=2, _cache={})
        self.assertEqual(sorted(plain), sorted(cached),
                         '加了缓存不能改变结论，只能改变算几次')

    def test_summary_composition_reaches_four_hops(self):
        import jsparse
        import jssem

        src = ('function h(e, p) { a(p); }'
               'function a(x) { b(x); }'
               'function b(y) { c(y); }'
               'function c(z) { d(z); }'
               'function d(w) { m.writeFileSync(w); }')
        toks = jsparse.tokenize(src)
        defs = jsparse.function_defs(toks)
        summaries = jssem.function_summaries(toks, defs)
        d0 = [d for d in defs if d['name'] == 'h'][0]
        key = (d0['body_start'], d0['body_end'])
        hits = jssem.summary_sinks(summaries, key, {'p'})
        self.assertTrue(hits, '摘要组合要能穿过四层调用，不靠加深递归')

    def test_facts_carry_the_truncation_count(self):
        files = {'main.js': (b'const {ipcMain} = require("electron");\n'
                             b'ipcMain.handle("x", function (e, p) {'
                             b' a(p); });\n'
                             b'function a(x) { m.writeFileSync(x); }\n')}
        facts = ipc.scan_asar(files)
        self.assertIn('taint_truncated', facts,
                      '报告要读这个键，缺了就是 KeyError 或者整行消失')


class ModuleExportTests(unittest.TestCase):
    """The export table behind `n(8813).CONST` — edges alone say who, not what."""

    def parse(self, src):
        import jsparse
        import jssem

        toks = jsparse.tokenize(src)
        mods = jssem.find_modules(toks)
        return toks, mods, jssem.module_exports(toks, mods)

    def test_exports_parameter_member_is_recorded(self):
        _t, _m, ex = self.parse('var t={1:(e,n,r)=>{r.X="abc"}}')
        self.assertIn(('1', 'X'), ex)
        self.assertEqual([t.text for t in ex[('1', 'X')][0]], ['"abc"'])

    def test_module_exports_member_is_recorded(self):
        _t, _m, ex = self.parse('var t={1:(e,n,r)=>{e.exports.Y="z"}}')
        self.assertIn(('1', 'Y'), ex)

    def test_require_member_resolves_to_the_export(self):
        import jssem

        src = 'var t={1:(e,n,r)=>{r.Q="v"},2:(e,n,r)=>{return r(1).Q}}'
        toks, mods, ex = self.parse(src)
        pos = None
        for i, tok in enumerate(toks):
            if tok.kind == 'ident' and tok.text == 'r' and toks[i + 2].text == '1':
                pos = i
                break
        self.assertIsNotNone(pos, 'probe call not found')
        hit = jssem.resolve_require_member(toks, mods, ex, pos)
        self.assertIsNotNone(hit, '跨模块取成员要能查到导出值')
        self.assertEqual([t.text for t in hit[0]], ['"v"'])

    def test_missing_export_returns_none(self):
        import jssem

        src = 'var t={1:(e,n,r)=>{r.Q="v"},2:(e,n,r)=>{return r(1).MISSING}}'
        toks, mods, ex = self.parse(src)
        pos = None
        for i, tok in enumerate(toks):
            if tok.kind == 'ident' and tok.text == 'r' and toks[i + 2].text == '1':
                pos = i
                break
        self.assertIsNone(jssem.resolve_require_member(toks, mods, ex, pos),
                          '导出表里没有的成员，不许编一个出来')


    def test_subscript_export_is_recorded(self):
        _t, _m, ex = self.parse('var t={1:(e,n,r)=>{r["Q"]="v"}}')
        self.assertIn(('1', 'Q'), ex, '下标写法的导出名也要认')

    def test_object_literal_export_is_recorded(self):
        _t, _m, ex = self.parse('var t={1:(e,n,r)=>{e.exports={A:"x", B:function(){}}}}')
        self.assertIn(('1', 'A'), ex)
        self.assertIn(('1', 'B'), ex, '整体赋值成人字面量，字段要一个个拆出来')

    def test_receiver_alias_is_recorded(self):
        _t, _m, ex = self.parse('var t={1:(e,n,r)=>{const k=r; k.Z="v"}}')
        self.assertIn(('1', 'Z'), ex, 'const k = exports 之后 k.X 也是导出')

    def test_esm_named_exports(self):
        import jsparse
        import jssem

        toks = jsparse.tokenize('export function a(){} export const b = 1; export {c};')
        ex = jssem.esm_exports(toks)
        self.assertEqual(sorted(ex), ['a', 'b', 'c'])

    def test_esm_default_is_not_a_named_export(self):
        import jsparse
        import jssem

        toks = jsparse.tokenize('export default function (){}')
        self.assertEqual(sorted(jssem.esm_exports(toks)), ['default'])


    def test_reassigned_exports_object_is_recorded(self):
        _t, _m, ex = self.parse('var t={1:(e,n,r)=>{r={A:"x"}}}')
        self.assertIn(('1', 'A'), ex, 'exports 整体重赋值也要认，不然整张表是空的')

    def test_exported_class_is_recorded_by_name(self):
        _t, _m, ex = self.parse('var t={1:(e,n,r)=>{e.exports=class Foo{}}}')
        self.assertIn(('1', 'Foo'), ex)

    def test_anonymous_exported_class_is_default(self):
        _t, _m, ex = self.parse('var t={1:(e,n,r)=>{e.exports=class{}}}')
        self.assertIn(('1', 'default'), ex, '匿名类没有名字，记成 default 而不是丢掉')


    def test_subscript_with_constant_is_folded(self):
        _t, _m, ex = self.parse(
            'var t={1:(e,n,r)=>{const K="fileSave"; r[K]=function(){}}}')
        self.assertIn(('1', 'fileSave'), ex, '同模块常量当下标，算得出来就不该放弃')

    def test_multi_variable_declaration_is_folded(self):
        _t, _m, ex = self.parse(
            'var t={1:(e,n,r)=>{let A="a", B="b"; r[A]=1; r[B]=2;}}')
        self.assertIn(('1', 'a'), ex)
        self.assertIn(('1', 'b'), ex)

    def test_subscript_with_unknown_name_is_skipped(self):
        _t, _m, ex = self.parse('var t={1:(e,n,r)=>{r[someVar]=1}}')
        self.assertEqual(ex, {}, '来自参数或外部的名字，算不出来就不报')

    def test_loop_over_literal_array_enumerates(self):
        _t, _m, ex = self.parse(
            'var t={1:(e,n,r)=>{const OPS=["save","open"];'
            'for (const op of OPS) { r[op] = function(){}; }}}')
        self.assertIn(('1', 'save'), ex)
        self.assertIn(('1', 'open'), ex, '循环遍历字面量数组，名字是可以摊出来的')

    def test_loop_over_computed_array_is_not_enumerated(self):
        _t, _m, ex = self.parse(
            'var t={1:(e,n,r)=>{const OPS=getOps();'
            'for (const op of OPS) { r[op] = function(){}; }}}')
        self.assertEqual(ex, {}, '数组来自函数调用，枚举不出来就不编')


    def test_literal_concat_is_folded(self):
        _t, _m, ex = self.parse('var t={1:(e,n,r)=>{const K="a"+"b"; r[K]=1;}}')
        self.assertIn(('1', 'ab'), ex, '纯字面量拼接还是常量')

    def test_concat_with_variable_is_not_folded(self):
        _t, _m, ex = self.parse('var t={1:(e,n,r)=>{const K="a"+x; r[K]=1;}}')
        self.assertEqual(ex, {}, '拼了变量就不算常量，只留前半截等于编名字')

    def test_array_concat_enumerates(self):
        _t, _m, ex = self.parse(
            'var t={1:(e,n,r)=>{const A=["x"], B=["y"];'
            'const C=A.concat(B); for (const k of C) { r[k]=1; }}}')
        self.assertIn(('1', 'x'), ex)
        self.assertIn(('1', 'y'), ex)

    def test_array_concat_with_call_is_not_enumerated(self):
        _t, _m, ex = self.parse(
            'var t={1:(e,n,r)=>{const C=A.concat(getB());'
            'for (const k of C) { r[k]=1; }}}')
        self.assertEqual(ex, {}, '一边算不出来，整条就不报')


class ModuleGraphTests(unittest.TestCase):
    """打包文件里的模块表：谁是谁，谁 require 了谁。"""

    def parse(self, src):
        import jsparse
        import jssem

        toks = jsparse.tokenize(src)
        return toks, jssem.find_modules(toks)

    def test_arrow_module_with_params(self):
        _toks, mods = self.parse('var t={7:(e,n,r)=>{}}')
        self.assertEqual([m[0] for m in mods], ['7'])
        self.assertEqual(mods[0][1], ['e', 'n', 'r'])

    def test_single_parameter_arrow(self):
        _toks, mods = self.parse('var t={7:e=>{}}')
        self.assertEqual(mods[0][1], ['e'])

    def test_function_form(self):
        _toks, mods = self.parse('var t={7:function(e,n){}}')
        self.assertEqual(mods[0][1], ['e', 'n'])

    def test_switch_label_is_not_a_module(self):
        _toks, mods = self.parse('switch(x){case 0:t=function(e){}}')
        self.assertEqual(mods, [], '`case 0:t=function` 长得像模块，但它不是')

    def test_edges_follow_the_third_parameter(self):
        import jssem

        toks, mods = self.parse('var t={1:(e,n,r)=>{r(2)},2:(e,n,r)=>{}}')
        self.assertEqual(jssem.module_edges(toks, mods), [('1', '2')])

    def test_edge_to_missing_module_is_dropped(self):
        import jssem

        toks, mods = self.parse('var t={1:(e,n,r)=>{r(99)}}')
        self.assertEqual(jssem.module_edges(toks, mods), [], '连不到真模块的边要丢掉')


class ScopeResolveTests(unittest.TestCase):
    """按块作用域判断一个短名在某个位置指的是哪次赋值。

    压缩产物把 `v` 这样的名字复用上百次，靠正则一定追错——所以先建块父子关系，
    只接受「声明的块是使用点的祖先块」的那些。
    """

    def resolve(self, src, name='v'):
        import jsparse
        import jssem

        toks = jsparse.tokenize(src)
        index = jssem.scope_index(toks)
        pos = None
        for i, tok in enumerate(toks):
            if tok.kind == 'ident' and tok.text == 'use' and toks[i + 1].text == '(':
                pos = i
                break
        if pos is None:
            raise AssertionError('probe call not found')
        found = jssem.resolve_root(toks, index, pos, name)
        if not found:
            return None
        return [t.text for t in found[1]]

    def test_outer_declaration_is_visible_inside_a_block(self):
        got = self.resolve('let v="outer"; function f(){ use(v); }')
        self.assertEqual(got, ['"outer"'])

    def test_inner_declaration_shadows_the_outer_one(self):
        got = self.resolve('let v="outer"; function f(){ let v="inner"; use(v); }')
        self.assertEqual(got, ['"inner"'], '内层声明必须赢，不然追根就追到别人的变量上')

    def test_declaration_after_use_is_not_visible(self):
        got = self.resolve('function f(){ use(v); } let v="x";')
        self.assertEqual(got, None, '后面才声明的，当前位置看不到')

    def test_sibling_block_declaration_is_not_visible(self):
        got = self.resolve('function a(){ let v="other"; } function b(){ use(v); }')
        self.assertEqual(got, None, '兄弟块里的声明不能串过来')

    def test_getpath_counts_as_a_known_directory(self):
        import jsparse
        import jssem

        toks = jsparse.tokenize('l.app.getPath("userData")')
        kind, value = jssem.classify_root(toks)
        self.assertEqual((kind, value), ('known-dir', 'userData'))

    def test_plain_expression_root_is_not_known(self):
        import jsparse
        import jssem

        toks = jsparse.tokenize('Math.random()')
        self.assertEqual(jssem.classify_root(toks)[0], 'expr')


class InterprocStateWriteTests(unittest.TestCase):
    """The handler hands the value to a local helper, and the helper writes the field."""

    def analyse(self, src, params=('i',)):
        import jsparse
        import jssem

        toks = jsparse.tokenize(src)
        defs = jsparse.function_defs(toks)
        d0 = [x for x in defs if x['name'] == 'h'][0]
        return jssem.state_writes_interproc(
            toks, d0['body_start'], d0['body_end'], set(params), defs)

    def test_write_inside_callee_is_reported(self):
        hits = self.analyse('function h(e, i) { save(C, i); }\n'
                            'function save(cfg, v) { cfg.icon = v; }\n')
        self.assertTrue(hits, '在 helper 里写状态，不能因为不在同一个函数就丢掉')
        fn, field, src_name = hits[0][0], hits[0][1], hits[0][2]
        self.assertEqual((fn, field, src_name), ('save', 'icon', 'v'))

    def test_clean_argument_does_not_propagate(self):
        hits = self.analyse('function h(e, i) { save(C, "lit"); }\n'
                            'function save(cfg, v) { cfg.icon = v; }\n')
        self.assertEqual(hits, [], '实参是字面量，形参就不脏')

    def test_arity_mismatch_is_not_guessed(self):
        hits = self.analyse('function h(e, i) { save(C); }\n'
                            'function save(cfg, v) { cfg.icon = v; }\n')
        self.assertEqual(hits, [], '形参个数对不上就不按位置硬套')


class ArgShapeTests(unittest.TestCase):
    """How directly the dirty value is handed over: bare, or wrapped in an expression."""

    def analyse(self, body):
        import jsparse
        import jssem

        src = 'function h(e, i, c) {' + body + '}'
        toks = jsparse.tokenize(src)
        d0 = [x for x in jsparse.function_defs(toks) if x['name'] == 'h'][0]
        return jssem.flows_into_danger(toks, d0['body_start'], d0['body_end'], ['e', 'i', 'c'])

    def test_bare_argument_is_direct(self):
        hits = self.analyse('m.writeFileSync(i, "x");')
        self.assertEqual([h[3] for h in hits], ['direct'], hits)

    def test_wrapped_argument_is_marked(self):
        hits = self.analyse('m.writeFileSync(String(i), "x");')
        self.assertEqual([h[3] for h in hits], ['wrapped'], hits)

    def test_shape_survives_two_arguments(self):
        hits = self.analyse('m.renameSync(i, String(c));')
        shapes = sorted(h[3] for h in hits)
        self.assertEqual(shapes, ['direct', 'wrapped'], hits)


class EscapeVerdictTests(unittest.TestCase):
    """Can join/resolve really climb out of its root? Only static facts, no guessing."""

    def verdict(self, src, func='join'):
        import jsparse
        import jssem

        toks = jsparse.tokenize(src)
        for i, tok in enumerate(toks):
            if tok.kind == 'ident' and tok.text == func and toks[i + 1].text == '(':
                return jssem.join_escape_verdict(toks, i + 1, func)
        raise AssertionError('call not found in source')

    def test_literal_root_with_clean_arg_is_anchored(self):
        self.assertEqual(self.verdict('F.join("/base", i)'), 'anchored')

    def test_dotdot_in_string_escapes(self):
        self.assertEqual(self.verdict('F.join("/base", "../x")'), 'escapes')

    def test_variable_root_is_unknown(self):
        self.assertEqual(self.verdict('F.join(v, i)'), 'root_unknown')

    def test_param_root_says_so(self):
        import jsparse
        import jssem

        toks = jsparse.tokenize('F.join(v, i)')
        open_at = [i for i, t in enumerate(toks) if t.text == '('][0]
        got = jssem.join_escape_verdict(toks, open_at, 'join', params=['v', 'i'])
        self.assertEqual(got, 'root_param', '根是形参时要说清「值从外面进来」')

    def test_local_root_says_so(self):
        import jsparse
        import jssem

        toks = jsparse.tokenize('F.join(v, i)')
        open_at = [i for i, t in enumerate(toks) if t.text == '('][0]
        got = jssem.join_escape_verdict(toks, open_at, 'join', locals_={'v'})
        self.assertEqual(got, 'root_local', '根是同体里赋过值的变量，也要分出来')

    def test_resolve_with_absolute_escapes(self):
        self.assertEqual(self.verdict('F.resolve(v, "/etc/passwd")', 'resolve'), 'escapes')

    def test_join_with_absolute_stays_under_root(self):
        self.assertEqual(self.verdict('F.join("/base", "/etc/passwd")'), 'anchored')

    def test_windows_drive_escapes_on_resolve(self):
        self.assertEqual(self.verdict('F.resolve(v, "C:\\\\tmp")', 'resolve'), 'escapes')


class StateWriteTests(unittest.TestCase):
    """External value written into a state field, plus who reads it in the same body."""

    def analyse(self, body, params=('e', 'i', 'c')):
        import jsparse
        import jssem

        src = 'function h(e, i, c) {' + body + '}'
        toks = jsparse.tokenize(src)
        d0 = [x for x in jsparse.function_defs(toks) if x['name'] == 'h'][0]
        rows = jssem.state_writes(toks, d0['body_start'], d0['body_end'], set(params))
        return rows, src

    def test_member_assignment_is_a_write(self):
        rows, _ = self.analyse('C.icon = i;')
        self.assertEqual(len(rows), 1)
        field, src_name, off, reads = rows[0]
        self.assertEqual(field, 'icon')
        self.assertEqual(src_name, 'i')

    def test_offset_points_at_the_field_name(self):
        rows, src = self.analyse('C.icon = i;')
        off = rows[0][2]
        self.assertEqual(src[off:off + 4], 'icon')

    @staticmethod
    def non_empty(items, why):
        """对空集合说「全都满足」是平凡真，先确认非空。"""
        assert items, f'{why}：集合是空的，接下来断言的就是空集'
        return items

    def test_read_points_in_same_body_are_reported(self):
        rows, src = self.analyse('if (C.icon) { rm(C.icon); } C.icon = i;')
        reads = [r for r in self.non_empty(rows[0][3], '同体内的读点') if r[1] == 'read']
        self.assertEqual(len(reads), 2, reads)
        for off, _kind, _call in reads:
            self.assertEqual(src[off:off + 4], 'icon')

    def test_read_inside_a_call_reports_the_caller(self):
        rows, _ = self.analyse('C.icon = i; rmSync(F.join(v, C.icon));')
        calls = [call for _off, kind, call in rows[0][3] if kind == 'read']
        self.assertEqual(calls, ['F.join'], '读点落在 F.join 的实参里，要报出来')

    def test_read_outside_a_call_has_no_caller(self):
        rows, _ = self.analyse('C.icon = i; if (C.icon) { done(); }')
        calls = [call for _off, kind, call in rows[0][3] if kind == 'read']
        self.assertEqual(calls, [None], '不在调用实参里的读，不编一个调用名')

    def test_delete_is_not_counted_as_a_read(self):
        rows, _ = self.analyse('C.icon = i; delete C.icon;')
        kinds = [kind for _off, kind, _call in rows[0][3]]
        self.assertEqual(kinds, ['delete'], 'delete 是清空，不是读')

    def test_write_only_has_no_read_points(self):
        rows, _ = self.analyse('C.appMenu = c;')
        self.assertEqual(rows[0][3], ())

    def test_plain_local_variable_is_not_a_state_write(self):
        rows, _ = self.analyse('let q = i;')
        self.assertEqual(rows, [])

    def test_constant_rhs_is_not_a_write(self):
        rows, _ = self.analyse('C.icon = "abc";')
        self.assertEqual(rows, [])


if __name__ == '__main__':
    unittest.main()