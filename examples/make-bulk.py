"""生成 bulk-asar 靶子：八百条通道，看报告会不会散架。

不是手写的，是生成的——八百行手写没意义，要的是数量。

    python examples/make-bulk.py
"""
import json
import os

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'bulk-asar')
COUNT = 800


def main():
    src = os.path.join(ROOT, 'src')
    os.makedirs(src, exist_ok=True)

    handlers = []
    members = []
    for i in range(COUNT):
        name = f'bulk:chan{i:04d}'
        handlers.append(
            f"ipcMain.handle('{name}', (event, payload) => ({{ ok: true, i: {i} }}));")
        members.append(f"    m{i:04d}: (p) => ipcRenderer.invoke('{name}', p),")

    main_js = (
        "const { app, BrowserWindow, ipcMain } = require('electron');\n"
        "app.whenReady().then(() => {\n"
        "  const win = new BrowserWindow({\n"
        "    webPreferences: {\n"
        "      preload: __dirname + '/preload.js',\n"
        "      contextIsolation: true,\n"
        "      nodeIntegration: false\n"
        "    }\n"
        "  });\n"
        "  win.loadFile('index.html');\n"
        "});\n\n"
        + "\n".join(handlers) + "\n"
    )

    preload_js = (
        "const { contextBridge, ipcRenderer } = require('electron');\n\n"
        "contextBridge.exposeInMainWorld('bulk', {\n"
        + "\n".join(members) + "\n"
        "});\n"
    )

    with open(os.path.join(src, 'main.js'), 'w', encoding='utf-8') as fh:
        fh.write(main_js)
    with open(os.path.join(src, 'preload.js'), 'w', encoding='utf-8') as fh:
        fh.write(preload_js)
    with open(os.path.join(ROOT, 'package.json'), 'w', encoding='utf-8') as fh:
        json.dump({'name': 'bulk-target', 'version': '0.0.1', 'main': 'src/main.js'},
                  fh, ensure_ascii=False, indent=2)

    print(f'wrote {ROOT} — {COUNT} 条通道')


if __name__ == '__main__':
    main()
