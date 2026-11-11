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


if __name__ == '__main__':
    unittest.main()
