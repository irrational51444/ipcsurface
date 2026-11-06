"""把一份真实报告渲染成一张图，放进 README。

只截结果，不截命令。图是这么来的，不是拼的：
先真跑一遍，再把那份报告画成 PNG。

    python scripts/render_preview.py out.md docs/preview.png
"""
import os
import sys

from PIL import Image, ImageDraw, ImageFont

BG = (13, 17, 23)
FG = (196, 204, 214)
DIM = (108, 118, 132)
HEAD = (126, 231, 165)
WARN = (255, 166, 87)
CODE = (121, 192, 255)
RULE = (48, 54, 61)

FONT_CANDIDATES = [
    r'C:\Windows\Fonts\msyh.ttc',
    '/System/Library/Fonts/PingFang.ttc',
    '/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc',
]

WIDTH = 1120
PAD = 36
LINE_H = 28
MAX_LINES = 52
MAX_CHARS = 78


def pick_font(size):
    for path in FONT_CANDIDATES:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def shorten(line):
    if len(line) <= MAX_CHARS:
        return line
    return line[:MAX_CHARS - 1] + '…'


def draw_rich(draw, x, y, text, font):
    """把 `反引号` 那段换个颜色画。"""
    for i, part in enumerate(text.split('`')):
        if not part:
            continue
        draw.text((x, y), part, font=font, fill=CODE if i % 2 else FG)
        x += draw.textlength(part, font=font)


def classify(line):
    stripped = line.strip()
    if stripped.startswith('[OK]'):
        return 'ok'
    if stripped.startswith('[FAIL]'):
        return 'bad'
    if stripped.startswith('----'):
        return 'summary'
    if stripped.startswith('###'):
        return 'h3'
    if stripped.startswith('##'):
        return 'h2'
    if stripped.startswith('#'):
        return 'h1'
    if stripped.startswith('|---') or stripped.startswith('| ---'):
        return 'skip'
    if stripped.startswith('|'):
        return 'table'
    if stripped.startswith('>'):
        return 'quote'
    if stripped.startswith('- ['):
        return 'finding'
    if stripped.startswith('-'):
        return 'li'
    if not stripped:
        return 'blank'
    return 'para'


def main():
    if len(sys.argv) < 2:
        print('用法: python scripts/render_preview.py <报告.md> [输出.png]', file=sys.stderr)
        return 2
    source = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else 'preview.png'
    title = sys.argv[3] if len(sys.argv) > 3 else 'ipcsurface app.asar -o surface.md'

    with open(source, encoding='utf-8-sig') as fh:
        raw = fh.read().splitlines()

    body = []
    for line in raw:
        kind = classify(line)
        if kind == 'skip':
            continue
        if kind == 'blank' and (not body or body[-1][0] == 'blank'):
            continue
        body.append((kind, line.rstrip()))
    body = body[:MAX_LINES]

    font = pick_font(17)
    font_head = pick_font(22)

    # 画布先按最多的行数留够，最后再裁掉底下空白
    rough = PAD * 2 + 90 + len(body) * (LINE_H + 6)
    img = Image.new('RGB', (WIDTH, rough), BG)
    draw = ImageDraw.Draw(img)
    y = PAD

    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        draw.ellipse([PAD + i * 22, y - 8, PAD + i * 22 + 12, y + 4], fill=c)
    y += 26
    draw.text((PAD, y), title, font=font, fill=DIM)
    y += LINE_H + 6
    draw.line([(PAD, y), (WIDTH - PAD, y)], fill=RULE)
    y += 14

    for kind, line in body:
        if kind == 'h1':
            draw.text((PAD, y), line.lstrip('# ').strip(), font=font_head, fill=HEAD)
            y += LINE_H + 4
        elif kind == 'h2':
            draw.text((PAD, y), line.lstrip('# ').strip(), font=font, fill=HEAD)
            y += LINE_H
        elif kind in ('ok', 'bad'):
            mark, rest = ('√', line.strip()[4:].strip()) if kind == 'ok' else ('×', line.strip()[5:].strip())
            draw.text((PAD + 2, y), mark, font=font, fill=(63, 185, 80) if kind == 'ok' else (248, 81, 73))
            draw.text((PAD + 26, y), shorten(rest), font=font, fill=FG if kind == 'ok' else WARN)
            y += LINE_H
        elif kind == 'summary':
            draw.text((PAD, y), line.strip(), font=font, fill=HEAD)
            y += LINE_H
        elif kind == 'finding':
            text = line.strip()
            level = 'high' if text.startswith('- [high]') else (
                'medium' if text.startswith('- [medium]') else 'info')
            body = text.split(']', 1)[1].strip() if ']' in text else text
            dot = {'high': (248, 81, 73), 'medium': WARN, 'info': DIM}[level]
            draw.ellipse([PAD + 2, y + 8, PAD + 10, y + 16], fill=dot)
            draw_rich(draw, PAD + 20, y, shorten(body), font)
            y += LINE_H
        elif kind == 'li':
            draw.text((PAD + 6, y), '·', font=font, fill=DIM)
            draw_rich(draw, PAD + 22, y, shorten(line.lstrip('- ')), font)
            y += LINE_H
        elif kind == 'table':
            cells = [c.strip() for c in line.strip('|').split('|')]
            draw_rich(draw, PAD + 4, y, shorten('  '.join(cells)), font)
            y += LINE_H
        elif kind == 'quote':
            draw_rich(draw, PAD + 4, y, shorten(line.lstrip('> ')), font)
            y += LINE_H
        elif kind == 'blank':
            y += int(LINE_H * 0.5)
        else:
            draw_rich(draw, PAD, y, shorten(line), font)
            y += LINE_H

    height = y + PAD
    img = img.crop((0, 0, WIDTH, height))
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    img.save(out, 'PNG')
    print(f'wrote {out} — {WIDTH}x{height}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
