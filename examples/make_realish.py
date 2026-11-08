"""造一个「像真项目」的靶场：几千个文件、几层 node_modules、固定内容。

为什么要它：以前「真包基准」（22102 文件 / 41 条通道）只挂在作者本机的
一个 Electron 应用上，换台机器就 SKIP。这个靶场是生成出来的，谁都能造，
CI 里能跑，用来守三件事：规模、通道数、性能。

内容全是确定的，所以期望值是固定的：`realish.asar` = 3000 个文件、
12 条不同名字的通道。
"""
import json
import os
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(HERE, 'realish-asar')

CHANNELS = [
    'app:ready',
    'window:minimize',
    'window:maximize',
    'window:close',
    'fs:read',
    'fs:write',
    'dialog:open',
    'dialog:save',
    'update:check',
    'settings:get',
    'settings:set',
    'log:tail',
]

MODULES = 40          # 每层模块数
FILES_PER_MODULE = 74  # 每个模块的文件数 —— 40*74 + 主干 ≈ 3000


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(text)


def main():
    if os.path.isdir(TARGET):
        shutil.rmtree(TARGET)
    os.makedirs(TARGET)

    write(os.path.join(TARGET, 'package.json'),
          json.dumps({'name': 'realish', 'version': '1.0.0', 'main': 'main.js'},
                     ensure_ascii=False, indent=2) + '\n')

    handlers = '\n'.join(
        f"ipcMain.handle('{name}', async () => null)  // {name}" for name in CHANNELS)
    write(os.path.join(TARGET, 'main.js'),
          "const { ipcMain, app, BrowserWindow } = require('electron')\n\n"
          + handlers + '\n\napp.whenReady().then(() => { new BrowserWindow({}) })\n')

    # 一层 node_modules：模块多、文件多，但不写死通道名，只是体量
    for m in range(MODULES):
        name = f'mod-{m:02d}'
        base = os.path.join(TARGET, 'node_modules', name)
        write(os.path.join(base, 'package.json'),
              json.dumps({'name': name, 'version': '1.0.0'}) + '\n')
        write(os.path.join(base, 'index.js'),
              f'module.exports = {{ id: {m} }}\n')
        for f in range(FILES_PER_MODULE):
            write(os.path.join(base, 'lib', f'part-{f:03d}.js'),
                  f'// {name} part {f}\nexports.value = {m * 1000 + f}\n')

    total = sum(len(files) for _root, _dirs, files in os.walk(TARGET))
    print(f'realish-asar 就绪：{total} 个文件，12 条通道')


if __name__ == '__main__':
    main()
