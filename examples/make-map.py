"""造一个带 sourcemap 的靶子。

bundle 是压过的，通道名一个都不在代码里；只有 .map 的 sourcesContent
里还留着原样的源码。这个靶子专门验一件事：包里带着 sourcemap 的时候，
工具能不能翻回去把名字捞出来。

    python examples/make-map.py
"""
import json
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))

ORIGINAL = """const { ipcMain } = require('electron');
ipcMain.handle('vault:unlock', (e, p) => p);
ipcMain.handle('vault:__export_all', () => null);
"""

MINIFIED = "var a=require('electron');a.ipcMain.handle(b.c,d),a.ipcMain.handle(e,f);"


def main():
    sourcemap = json.dumps({
        'version': 3,
        'file': 'bundle.min.js',
        'sources': ['../src/vault.ts'],
        'sourcesContent': [ORIGINAL],
        'mappings': '',
    }).encode()
    pkg = json.dumps({'name': 'map-target', 'main': 'dist/bundle.min.js'}).encode()
    mini = MINIFIED.encode()

    header = {
        'files': {
            'package.json': {'size': len(pkg), 'offset': '0'},
            'dist': {'files': {
                'bundle.min.js': {'size': len(mini), 'offset': str(len(pkg))},
                'bundle.min.js.map': {'size': len(sourcemap),
                                      'offset': str(len(pkg) + len(mini))},
            }},
        }
    }

    payload_json = json.dumps(header).encode()
    inner = struct.pack('<I', len(payload_json)) + payload_json
    payload = struct.pack('<I', len(inner)) + inner
    head = struct.pack('<I', 4) + struct.pack('<I', len(payload))

    out = os.path.join(HERE, 'map.asar')
    with open(out, 'wb') as fh:
        fh.write(head + payload + pkg + mini + sourcemap)
    print(f'wrote {out}')


if __name__ == '__main__':
    main()
