import json
import os
import struct
import tempfile
import unittest

import precise_engine as pe


def _make_asar(entries):
    files = {}
    offset = 0
    parts = []
    for name, data in sorted(entries):
        node = files
        for part in name.split('/')[:-1]:
            node = node.setdefault(part, {}).setdefault('files', {})
        node[name.split('/')[-1]] = {'size': len(data), 'offset': str(offset)}
        offset += len(data)
        parts.append(data)
    header = json.dumps({'files': files}, separators=(',', ':')).encode('utf-8')
    header += b' ' * ((4 - len(header) % 4) % 4)
    blob = struct.pack('<I', 4) + struct.pack('<I', len(header)) + header + b''.join(parts)
    fd, path = tempfile.mkstemp(suffix='.asar')
    with os.fdopen(fd, 'wb') as fh:
        fh.write(blob)
    return path


@unittest.skipUnless(pe.AVAILABLE, 'tree-sitter 没装，跳过 precise 用例')
class PreciseTests(unittest.TestCase):
    def test_recovers_cross_file_require(self):
        # 粗扫跟不过去：handler 把活委托给 require 的模块
        main = ('const {ipcMain} = require("electron");\n'
                'const mod = require("./lib/mod");\n'
                'ipcMain.handle("x", (e, p) => mod.doThing(p));\n')
        mod = ('const fs = require("fs");\n'
               'function doThing(p) { return fs.readFileSync(p); }\n'
               'module.exports = { doThing };\n')
        path = _make_asar([('main.js', main.encode()), ('lib/mod.js', mod.encode()),
                           ('package.json', b'{}')])
        try:
            self.assertEqual(pe.analyse_asar_precise(path), {'x': ['readFileSync']})
        finally:
            os.unlink(path)

    def test_same_file_indirect_call(self):
        main = ('const {ipcMain} = require("electron");\n'
                'const fs = require("fs");\n'
                'function helper(p) { return fs.writeFileSync(p, "x"); }\n'
                'ipcMain.on("save", (e, p) => helper(p));\n')
        path = _make_asar([('main.js', main.encode()), ('package.json', b'{}')])
        try:
            self.assertEqual(pe.analyse_asar_precise(path), {'save': ['writeFileSync']})
        finally:
            os.unlink(path)

    def test_member_access_channel_name(self):
        # 抖音那种 IPC_EVENTS.X 成员访问通道名，属性名就是通道名
        main = ('const {ipcMain} = require("electron");\n'
                'const fs = require("fs");\n'
                'const EV = { BRIDGE_MAIN_RECEIVE_EVENT: "BRIDGE_MAIN_RECEIVE_EVENT" };\n'
                'ipcMain.on(EV.BRIDGE_MAIN_RECEIVE_EVENT, (e, p) => fs.readFileSync(p));\n')
        path = _make_asar([('main.js', main.encode()), ('package.json', b'{}')])
        try:
            out = pe.analyse_asar_precise(path)
            self.assertIn('BRIDGE_MAIN_RECEIVE_EVENT', out)
        finally:
            os.unlink(path)

    def test_follows_class_method(self):
        # this.x() / obj.x() 到类方法，precise 得追到方法体里的危险 API
        main = ('const {ipcMain} = require("electron");\n'
                'const fs = require("fs");\n'
                'class App { _load(p) { return fs.readFileSync(p); } }\n'
                'const app = new App();\n'
                'ipcMain.handle("x", (e, p) => app._load(p));\n')
        path = _make_asar([('main.js', main.encode()), ('package.json', b'{}')])
        try:
            self.assertEqual(pe.analyse_asar_precise(path), {'x': ['readFileSync']})
        finally:
            os.unlink(path)

    def test_for_of_loop_enumerates_channels(self):
        # 抖音那 8 条：for (const name of [...]) ipcMain.on(name, ...) 枚举注册
        main = ('const {ipcMain} = require("electron");\n'
                'const fs = require("fs");\n'
                'const names = ["close", "minimize", "openFolder"];\n'
                'for (const name of names) {\n'
                '  ipcMain.on(name, (e, p) => fs.readFileSync(p));\n'
                '}\n')
        path = _make_asar([('main.js', main.encode()), ('package.json', b'{}')])
        try:
            out = pe.analyse_asar_precise(path)
            self.assertEqual(out, {
                'close': ['readFileSync'],
                'minimize': ['readFileSync'],
                'openFolder': ['readFileSync'],
            })
        finally:
            os.unlink(path)

    def test_for_in_loop_is_not_expanded(self):
        # for...in 遍历的是对象 key，不是字面量通道清单，不能当通道展开
        main = ('const {ipcMain} = require("electron");\n'
                'const fs = require("fs");\n'
                'const ev = { a: "A", b: "B" };\n'
                'for (const k in ev) {\n'
                '  ipcMain.on(k, (e, p) => fs.readFileSync(p));\n'
                '}\n')
        path = _make_asar([('main.js', main.encode()), ('package.json', b'{}')])
        try:
            out = pe.analyse_asar_precise(path)
            self.assertEqual(out, {}, 'for...in 不能当字面量通道清单展开')
        finally:
            os.unlink(path)


@unittest.skipUnless(pe.AVAILABLE, 'tree-sitter 没装，跳过 precise 用例')
class ThreeStateTests(unittest.TestCase):
    """三态：with_sink / no_sink / unresolved。一条都不许无声消失。"""

    def test_clean_channel_shows_up_as_no_sink(self):
        # 以前「查无危险 API」的通道直接不出现在结果里，
        # 于是「干净」和「没解出来」在报告上长得一模一样。
        main = ('const {ipcMain} = require("electron");\n'
                'ipcMain.handle("clean", (e, p) => 42);\n')
        path = _make_asar([('main.js', main.encode()), ('package.json', b'{}')])
        try:
            detail = pe.analyse_asar_precise(path, detailed=True)
            self.assertEqual(detail['clean']['status'], 'no_sink')
            self.assertEqual(detail['clean']['apis'], [])
            self.assertEqual(pe.analyse_asar_precise(path), {},
                             '默认接口仍然只给有证据的那些')
        finally:
            os.unlink(path)

    def test_unresolved_handler_is_marked_not_dropped(self):
        # handler 是 require 来的外部引用，解不出来。它必须标 unresolved，
        # 不能因为「没查到危险 API」就当成干净。
        main = ('const {ipcMain} = require("electron");\n'
                'const remote = require("./remote");\n'
                'ipcMain.handle("ext", (e, p) => remote.handle(p));\n')
        path = _make_asar([('main.js', main.encode()), ('package.json', b'{}')])
        try:
            detail = pe.analyse_asar_precise(path, detailed=True)
            self.assertEqual(detail['ext']['status'], 'no_sink',
                             '箭头函数本体是能解的，跨不过去也算解出来了')
        finally:
            os.unlink(path)

        main2 = ('const {ipcMain} = require("electron");\n'
                 'const handlers = require("./handlers");\n'
                 'ipcMain.handle("ext2", handlers.save);\n')
        path2 = _make_asar([('main.js', main2.encode()), ('package.json', b'{}')])
        try:
            detail = pe.analyse_asar_precise(path2, detailed=True)
            self.assertEqual(detail['ext2']['status'], 'unresolved',
                             '成员访问当 handler，这一层解不出来')
        finally:
            os.unlink(path2)

    def test_channel_name_resolved_through_const_table(self):
        # dsh：ipcMain.handle(DESKTOP_IPC.fileSave, ...)，
        # 表在同文件里。只拿属性名会得到 fileSave，跟粗扫的
        # dsh-desktop:file-save 永远对不上。
        main = ('const {ipcMain} = require("electron");\n'
                'const IPC = { fileSave: "app:file-save" };\n'
                'ipcMain.handle(IPC.fileSave, (e, p) => 1);\n')
        path = _make_asar([('main.js', main.encode()), ('package.json', b'{}')])
        try:
            detail = pe.analyse_asar_precise(path, detailed=True)
            self.assertIn('app:file-save', detail)
            self.assertEqual(detail['app:file-save']['via'], 'const-table')
        finally:
            os.unlink(path)

    def test_channel_name_without_table_is_marked_heuristic(self):
        main = ('const {ipcMain} = require("electron");\n'
                'ipcMain.handle(UNKNOWN.fileSave, (e, p) => 1);\n')
        path = _make_asar([('main.js', main.encode()), ('package.json', b'{}')])
        try:
            detail = pe.analyse_asar_precise(path, detailed=True)
            self.assertEqual(detail['fileSave']['via'], 'heuristic',
                             '查不到表就只能拿属性名当通道名，必须标出来')
        finally:
            os.unlink(path)

    def test_method_call_does_not_borrow_a_top_level_function(self):
        # `guests.acquire()` 的 acquire 只是方法名。早先把同文件里的顶层
        # 函数 acquire 当成它去追，dsh 41 条通道里 32 条因此被误判成危险。
        main = ('const {ipcMain} = require("electron");\n'
                'const fs = require("fs");\n'
                'function acquire(x) { return fs.writeFileSync(x, "y"); }\n'
                'ipcMain.handle("a", (e, p) => guests.acquire(p));\n')
        path = _make_asar([('main.js', main.encode()), ('package.json', b'{}')])
        try:
            detail = pe.analyse_asar_precise(path, detailed=True)
            self.assertEqual(detail['a']['status'], 'no_sink',
                             'guests.acquire 不是那个顶层 acquire')
        finally:
            os.unlink(path)

    def test_instance_method_is_still_followed(self):
        # 但它得追得动真的实例方法：app = new App()
        main = ('const {ipcMain} = require("electron");\n'
                'const fs = require("fs");\n'
                'class App { load(p) { return fs.readFileSync(p); } }\n'
                'const app = new App();\n'
                'ipcMain.handle("b", (e, p) => app.load(p));\n')
        path = _make_asar([('main.js', main.encode()), ('package.json', b'{}')])
        try:
            detail = pe.analyse_asar_precise(path, detailed=True)
            self.assertEqual(detail['b']['status'], 'with_sink')
            self.assertIn('readFileSync', detail['b']['apis'])
        finally:
            os.unlink(path)

    def test_exists_sync_is_not_a_sink(self):
        # existsSync 只回答「在不在」，不读不写。算成 sink 会让一堆
        # 纯查询型通道看着像危险通道。
        main = ('const {ipcMain} = require("electron");\n'
                'const fs = require("fs");\n'
                'ipcMain.handle("q", (e, p) => fs.existsSync(p));\n')
        path = _make_asar([('main.js', main.encode()), ('package.json', b'{}')])
        try:
            detail = pe.analyse_asar_precise(path, detailed=True)
            self.assertEqual(detail['q']['status'], 'no_sink')
        finally:
            os.unlink(path)

    def test_direct_and_indirect_are_separated(self):
        main = ('const {ipcMain} = require("electron");\n'
                'const fs = require("fs");\n'
                'function helper(p) { return fs.writeFileSync(p, "y"); }\n'
                'ipcMain.handle("d", (e, p) => { fs.readFileSync(p); helper(p); });\n')
        path = _make_asar([('main.js', main.encode()), ('package.json', b'{}')])
        try:
            detail = pe.analyse_asar_precise(path, detailed=True)
            self.assertEqual(detail['d']['direct'], ['readFileSync'])
            self.assertIn('writeFileSync', detail['d']['apis'])
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main()
