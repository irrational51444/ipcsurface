# -*- coding: utf-8 -*-
"""把真实跑出来的终端输出渲染成 PNG，给 README 当截图。

不是截屏，是按字符画——好处是内容一定和当前版本对得上，
不会出现「图上是旧版、文字是新版」那种自己骗自己的局面。
"""
import os
import subprocess
import sys
import textwrap

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'docs', 'img')

# 微软雅黑：中英都像样，字号 15 在 1200 宽里一行约 100 个英文字符
FONT_CANDIDATES = [
    r'C:\Windows\Fonts\msyh.ttc',
    r'C:\Windows\Fonts\msyhbd.ttc',
    r'C:\Windows\Fonts\simhei.ttf',
]
BG = (18, 20, 24)
FG = (214, 219, 224)
DIM = (120, 128, 136)
ACCENT = (120, 200, 140)
LINE_H = 22
PAD = 22


def font(size=15):
    for path in FONT_CANDIDATES:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _wrap(line, f, max_w):
    """按像素宽度折行。报告里有很长的行（复算指纹），不折就被切掉。"""
    if f.getlength(line) <= max_w:
        return [line]
    out, cur = [], ''
    for ch in line:
        if f.getlength(cur + ch) > max_w:
            out.append(cur)
            cur = ch
        else:
            cur += ch
    if cur:
        out.append(cur)
    return out


def render(title, lines, filename, width=1180, max_lines=None):
    if max_lines:
        lines = lines[:max_lines]
    f = font()
    ft = font(14)
    # 先折行再算高度，不然图会短一截
    wrapped = []
    for line in lines:
        wrapped.extend(_wrap(line, f, width - PAD * 2))
    lines = wrapped
    height = PAD * 2 + 30 + LINE_H * len(lines)
    img = Image.new('RGB', (width, height), BG)
    d = ImageDraw.Draw(img)
    # 标题栏
    d.rectangle([0, 0, width, 30], fill=(30, 33, 38))
    d.text((PAD, 8), title, font=ft, fill=DIM)
    y = 30 + PAD
    for line in lines:
        color = FG
        if line.startswith('$'):
            color = ACCENT
        elif line.startswith('#') or line.startswith('=='):
            color = (140, 180, 230)
        d.text((PAD, y), line, font=f, fill=color)
        y += LINE_H
    path = os.path.join(OUT, filename)
    img.save(path)
    print('wrote', path, '%dx%d' % img.size)
    return path


def run(cmd, cwd=ROOT):
    env = dict(os.environ, PYTHONIOENCODING='utf-8')
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          encoding='utf-8', errors='replace', env=env,
                          shell=False)
    return (proc.stdout or '') + (proc.stderr or '')
