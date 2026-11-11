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


if __name__ == '__main__':
    unittest.main()
