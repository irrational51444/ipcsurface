"""造一个「靶场」样品：三条通道，一条安全、一条写文件、一条执行命令。

README 的第一个例子就用它——谁都能一条命令造出来，不依赖我的机器。
刻意做小：能一眼看完，也能对着源码确认工具说的对不对。
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.make_scale_asar import build_asar  # noqa: E402

MAIN = r"""const { ipcMain, shell } = require('electron');
const fs = require('fs');
const path = require('path');

// 1) 安全的：路径是自己拼的，用户传进来的只是名字
ipcMain.handle('demo:ping', async (event, who) => {
  return 'pong ' + String(who);
});

// 2) 会写文件，而且路径直接来自渲染进程
ipcMain.handle('demo:save-note', async (event, note) => {
  fs.writeFileSync(note.path, note.body);
  return true;
});

// 3) 会把外部字符串拼进命令
ipcMain.handle('demo:run', async (event, cmd) => {
  const { exec } = require('child_process');
  exec('sh -c ' + cmd);
  return 'started';
});

// 4) 一个谁都能看出来的后台注册
ipcMain.on('demo:tick', () => {});
"""

PRELOAD = r"""const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('demo', {
  ping: (who) => ipcRenderer.invoke('demo:ping', who),
  saveNote: (note) => ipcRenderer.invoke('demo:save-note', note),
  run: (cmd) => ipcRenderer.invoke('demo:run', cmd),
});
"""


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'build', 'demo.asar')
    entries = [
        ('package.json', b'{"name":"ipcsurface-demo","main":"main.js"}'),
        ('main.js', MAIN.encode('utf-8')),
        ('preload.js', PRELOAD.encode('utf-8')),
    ]
    build_asar(entries, out)
    print('写好 %s：%d 个文件，%.1f KB' % (out, len(entries),
                                         os.path.getsize(out) / 1024.0))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
