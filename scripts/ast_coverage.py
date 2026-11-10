"""量手写解析器在真包上的覆盖率：包级数字 + 未知节点的语法归因。

三个口径，别混：
  · 未知节点率 = kind == 'Other' 的节点占该包所有节点的比例（包级，不是平均）
  · 归因 = 未知节点最常见的几种记号长什么样（用来判断是哪类语法没认）
  · 吞吐 = 只算「建树」这一步，不含读 asar、不含粗扫

扫描上限（scan_cap）：最多取 max_files 个最大的 .js、总字节不超过 max_bytes，
不然 DeepSeek Harness 那种 200MB 的包跑不完。上限写在输出里，别让人以为扫了全包。
"""
import collections
import os
import sys
import time

ROOT = r'C:\Users\irrational\Desktop\rea-lab'
sys.path.insert(0, ROOT)

import ipcsurface as t  # noqa: E402
import jsast  # noqa: E402
import jsparse  # noqa: E402

PKGS = [
    ('obsidian', r'C:\Users\irrational\AppData\Local\Programs\Obsidian\resources\obsidian.asar'),
    ('dsh', r'C:\Users\irrational\AppData\Local\Programs\DeepSeek Harness\resources\app.asar'),
    ('douyin', r'C:\Program Files (x86)\ByteDance\douyin\8.8.0\resources\app.asar'),
    ('bilibili', r'C:\Program Files\bilibili\resources\app.asar'),
]


def measure(path, max_files=60, max_bytes=48 * 1024 * 1024):
    hdr, files = t.read_asar(path)
    try:
        names = [rel for rel in files.keys() if rel.endswith('.js') and files[rel]]
        names.sort(key=lambda rel: -len(files[rel]))
        picked, budget = [], 0
        for rel in names:
            size = len(files[rel])
            if len(picked) >= max_files or budget + size > max_bytes:
                break
            picked.append(rel)
            budget += size
        nodes = unknown = 0
        histogram = collections.Counter()
        unseen = collections.Counter()
        unterminated = 0
        seconds = 0.0
        kb = 0.0
        for rel in picked:
            text = files[rel].decode('utf-8', 'ignore')
            kb += len(text) / 1024.0
            started = time.time()
            program = jsast.parse(text)
            seconds += time.time() - started
            _, stats = jsparse.tokenize_with_stats(text)
            unseen.update(stats.get('unseen') or [])
            unterminated += len(stats.get('unterminated') or [])
            for node in jsast.walk(program):
                nodes += 1
                if node.kind == 'Other':
                    unknown += 1
                    histogram[str(node.value)[:12]] += 1
        return {
            'files': len(picked),
            'kb': kb,
            'seconds': seconds,
            'nodes': nodes,
            'unknown': unknown,
            'patterns': histogram.most_common(5),
            'unseen': unseen.most_common(5),
            'unterminated': unterminated,
            'capped': len(names) > len(picked),
        }
    finally:
        files.close()


def main():
    rows = []
    for label, path in PKGS:
        if not os.path.exists(path):
            print('%s: 本机没有，跳过' % label)
            continue
        data = measure(path)
        rate = 100.0 * data['unknown'] / max(data['nodes'], 1)
        speed = (data['kb'] / 1024.0) / max(data['seconds'], 1e-6)
        rows.append((label, data, rate, speed))
        print('=== %s（扫 %d 个文件%s，%.1f MB）'
              % (label, data['files'], '，封顶' if data['capped'] else '', data['kb'] / 1024.0))
        print('  未知节点率 %.2f%%（%d / %d）  建树吞吐 %.1f MB/s' % (rate, data['unknown'], data['nodes'], speed))
        print('  未知记号 top：%s' % (data['patterns'] or '无'))
        if data['unseen']:
            print('  认不出的字符：%s' % dict(data['unseen']))
        if data['unterminated']:
            print('  没闭合的字符串/模板/注释：%d 处（已软失败）' % data['unterminated'])
    if rows:
        worst = max(rows, key=lambda r: r[2])
        print('\n最高的一包：%s %.2f%%——下一个要看的样本就是它' % (worst[0], worst[2]))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
