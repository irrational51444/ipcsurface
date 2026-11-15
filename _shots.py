# -*- coding: utf-8 -*-
"""生成 README 用的图。数据源一律用 ipcsurface 自己 -o 写出来的文件，
不用 PowerShell 重定向——那个默认编码不是 UTF-8，读回来全是方块。"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import make_shots as ms  # noqa: E402

ROOT = ms.ROOT


def gen(asar, out):
    path = os.path.join(ROOT, out)
    ms.run([sys.executable, 'ipcsurface.py', asar, '-o', path])
    return read(out)


def read(path):
    return io.open(os.path.join(ROOT, path), encoding='utf-8-sig',
                   errors='replace').read().splitlines()


def clip(lines, start_kw, count):
    for i, line in enumerate(lines):
        if start_kw in line:
            return lines[i:i + count]
    return lines[:count]


OBS = (r'C:\Users\irrational\AppData\Local\Programs\Obsidian'
       r'\resources\obsidian.asar')

if not os.path.exists(os.path.join(ROOT, 'build/demo.asar')):
    ms.run([sys.executable, 'scripts/make_demo_asar.py', 'build/demo.asar'])

obs = gen(OBS, 'build/obs.md')
demo = gen(os.path.join('build', 'demo.asar'), 'build/demo.md')

ms.render('ipcsurface — Obsidian obsidian.asar (28 MB)',
          obs[:7] + [''] + clip(obs, '## 通道', 12), 'case-real-scan.png')

ms.render('python ipcsurface.py build/demo.asar',
          demo[:7] + [''] + clip(demo, '## 通道', 10)
          + [''] + clip(demo, '## 每个通道的证据', 9),
          'example-demo.png')

ms.render('每个通道都有一条判决（Obsidian）',
          clip(obs, '## 每个通道的证据', 15), 'example-obsidian.png')

out = ms.run(['C:\\Program Files\\Git\\bin\\bash.exe', 'scripts/verify.sh'])
ms.render('bash scripts/verify.sh', out.splitlines()[-24:], 'case-gates.png')
print('done')
