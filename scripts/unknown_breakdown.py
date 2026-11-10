"""把未知节点分成三栏：语法未知 / 解析器脱轨 / 数据问题。

为什么非分不可：8.34% 这个数字把三件完全不同的事混成一件——
  · 数据问题：文件本身被截断、加密、塞满控制字符。任何解析器都读不出语义，
    不该算在「语法覆盖」头上；
  · 解析器脱轨：逗号、右括号、冒号这种收尾标点成了未知节点，说明是**我的解析器**
    在某个构造上跑偏了，属于我该修的；
  · 语法未知：`#` 私有字段、`@` 装饰器、`<` JSX 这类「这门语法我没实现」。
判据写死在这儿，谁都能复核；每栏都带 file:line 样例。
"""
import collections
import os
import sys

ROOT = r'C:\Users\irrational\Desktop\rea-lab'
sys.path.insert(0, ROOT)

import ipcsurface as t  # noqa: E402
import jsast  # noqa: E402

DERRail = {',', ')', ':', ']', '}', ';', '(', '[', '{', '++', '--', '=',
           '=>', '.', '?.', '?'}
SYNTAX_HINTS = {'#', '@', '<', '>', '`', '$', '\\', '*', '&', '|', '!', '~'}


def is_data_char(text):
    """控制字符 / 替换符 / 纯不可打印 → 数据问题。"""
    if not text:
        return True
    return all(ord(ch) < 32 or ord(ch) == 0x7F or 0xE000 <= ord(ch) <= 0xF8FF
               for ch in text)


def classify(sample):
    text = str(sample.get('text', ''))
    if is_data_char(text):
        return 'data'
    if text in DERRail:
        return 'derail'
    return 'syntax'


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else \
        r'C:\Program Files (x86)\ByteDance\douyin\8.8.0\resources\app.asar'
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 60

    hdr, files = t.read_asar(path)
    try:
        names = [rel for rel in files.keys() if rel.endswith('.js') and files[rel]]
        names.sort(key=lambda rel: -len(files[rel]))
        picked = names[:limit]
        buckets = collections.defaultdict(collections.Counter)
        samples = collections.defaultdict(list)
        nodes = 0
        per_file = {}
        for rel in picked:
            text = files[rel].decode('utf-8', 'ignore')
            program = jsast.parse(text)
            unknown_here = 0
            for node in jsast.walk(program):
                nodes += 1
                if node.kind != 'Other':
                    continue
                unknown_here += 1
                info = node.value if isinstance(node.value, dict) else {'text': node.value, 'line': 0}
                kind = classify(info)
                buckets[kind][str(info.get('text'))[:12]] += 1
                if len(samples[kind]) < 5:
                    # 压缩产物一行几十万字符，只给行号等于没给。
                    # 补上列号和 40 字符上下文，人能肉眼定位到构造。
                    col = int(info.get('col') or 0)
                    snippet = text[max(0, col - 20):col + 20].replace('\n', ' ')
                    samples[kind].append('%s:%s:%s  记号 %r  上下文 …%s…'
                                         % (rel, info.get('line'), col,
                                            info.get('text'), snippet))
            per_file[rel] = unknown_here
    finally:
        files.close()

    total_unknown = sum(sum(b.values()) for b in buckets.values())
    print('包：%s' % path)
    print('扫 %d 个文件，节点 %d，未知 %d（%.2f%%）\n'
          % (len(picked), nodes, total_unknown, 100.0 * total_unknown / max(nodes, 1)))
    order = [('syntax', '语法未知（这门语法我没实现）'),
             ('derail', '解析器脱轨（收尾标点成未知，是我的 bug）'),
             ('data', '数据问题（截断/加密/控制字符，谁都读不出）')]
    for key, title in order:
        count = sum(buckets[key].values())
        rate = 100.0 * count / max(nodes, 1)
        print('%s：%d 处，占全节点 %.2f%%' % (title, count, rate))
        print('  高频记号：%s' % (buckets[key].most_common(4) or '无'))
        for line in samples[key]:
            print('    %s' % line)
        print()
    clean = 100.0 * (sum(buckets['syntax'].values()) + sum(buckets['derail'].values())) / max(nodes, 1)
    print('扣掉数据问题后的「语法未知率」：%.2f%%（语法 %d + 脱轨 %d，分母仍是全部节点）'
          % (clean, sum(buckets['syntax'].values()), sum(buckets['derail'].values())))
    worst = sorted(per_file.items(), key=lambda kv: -kv[1])[:3]
    print('未知节点最多的三个文件：')
    for rel, count in worst:
        print('  %-70s %d' % (rel[-70:], count))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
