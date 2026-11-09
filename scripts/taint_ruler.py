"""污点分析的尺子：一组带标准答案的片段，量检出率与误报率。

期望值三档：
  danger    —— 外部输入确实流到了危险 API，必须报
  clean     —— 不该报
  known-gap —— 明知现在会误报的（还没做中和分析）；单独计数，不算失败，
               但必须出现在输出里——藏起来才是问题
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import jsparse
import jssem

CASES = [
    ('直接流', """
function h(event, payload) {
  fs.writeFileSync(payload.path, 'x');
}
""", 'danger'),
    ('经一层局部变量', """
function h(event, payload) {
  const p = payload.path;
  fs.readFileSync(p);
}
""", 'danger'),
    ('经两层转手', """
function h(event, payload) {
  const a = payload;
  const b = a.path;
  fs.readFileSync(b);
}
""", 'danger'),
    ('成员直接进调用', """
function h(event, req) {
  return fetch(req.url);
}
""", 'danger'),
    ('经 helper 一层', """
function h(event, payload) {
  writeIt(payload.path);
}
function writeIt(p) {
  fs.writeFileSync(p, 'x');
}
""", 'danger'),
    ('常量路径不该报', """
function h(event) {
  fs.readFileSync('/etc/hostname');
}
""", 'clean'),
    ('正则 exec 不该报', """
function h(event, text) {
  const re = /a(b)c/;
  return re.exec(text);
}
""", 'clean'),
    ('参数没进危险调用', """
function h(event, payload) {
  return { ok: true, size: payload.length };
}
""", 'clean'),
    ('已校验后再用（已知缺口，会误报）', """
function h(event, payload) {
  if (payload.path !== '/safe') return;
  fs.readFileSync(payload.path);
}
""", 'known-gap'),
]


def analyse(source):
    tokens = jsparse.tokenize(source)
    defs = jsparse.function_defs(tokens)
    return jssem.interprocedural_hits(tokens, defs)


def main():
    caught = misses = false_alarms = known = broken = 0
    failures = []
    for name, source, expect in CASES:
        try:
            reported = bool(analyse(source))
        except (jsparse.ParseError, KeyError, TypeError) as exc:
            broken += 1
            failures.append((name, f'解析失败：{type(exc).__name__} {exc}'))
            continue
        if expect == 'danger':
            if reported:
                caught += 1
            else:
                misses += 1
                failures.append((name, '该报没报'))
        elif expect == 'known-gap':
            known += 1 if reported else 0
        else:
            if reported:
                false_alarms += 1
                failures.append((name, '不该报却报了'))

    danger = sum(1 for _n, _s, e in CASES if e == 'danger')
    clean = sum(1 for _n, _s, e in CASES if e == 'clean')
    print(f'正样本 {danger}：检出 {caught}，漏 {misses}，检出率 {caught / danger:.2f}')
    print(f'负样本 {clean}：误报 {false_alarms}，误报率 {false_alarms / clean:.2f}')
    print(f'已知缺口（已校验后使用）：{known} 条，不计入误报')
    if broken:
        print(f'解析失败：{broken} 条')
    for name, why in failures:
        print(f'  · {name}：{why}')
    print('注：这几个片段是我自己写的，覆盖的是已支持的语言子集，不代表真实代码。')
    return 0 if not failures else 1


if __name__ == '__main__':
    raise SystemExit(main())
