"""污点分析的尺子：一组带标准答案的片段，量检出率与误报率。

期望值三档：
  danger    —— 外部输入确实流到了危险 API，必须报
  clean     —— 不该报
  known-gap —— 明知现在会误报的；单独计数，不算失败，但必须出现在输出里
  unsupported —— 明知抓不到的（这条链路要求跨语句的抛出传播）；同样单独计数并列出
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
    ('回调里的形参', """
function h(event, payload) {
  return payload.list.map(v => fs.readFileSync(v));
}
""", 'danger'),
    ('模板串拼进命令', """
function h(event, payload) {
  const cmd = `ls ${payload.dir}`;
  execSync(cmd);
}
""", 'danger'),
    ('只校验 path，name 仍进危险调用', """
function h(event, payload) {
  if (payload.path !== '/safe') return;
  fs.readFileSync(payload.name);
}
""", 'danger'),
    ('校验 path 且只用 path', """
function h(event, payload) {
  if (payload.path !== '/safe') return;
  fs.readFileSync(payload.path);
}
""", 'clean'),
    ('for of 循环变量', """
function h(event, payload) {
  for (const item of payload.list) {
    fs.readFileSync(item);
  }
}
""", 'danger'),
    ('把函数名当回调传（已知缺口）', """
function handle(item) {
  fs.readFileSync(item);
}
function h(event, payload) {
  payload.list.map(handle);
}
""", 'danger'),
    ('for-in 枚举（已知缺口）', """
function h(event, payload) {
  for (const key in payload.map) {
    fs.readFileSync(payload.map[key]);
  }
}
""", 'danger'),
    ('函数式校验后使用', """
function h(event, payload) {
  if (!isSafe(payload.path)) return;
  fs.readFileSync(payload.path);
}
""", 'clean'),
    ('数组白名单校验后使用', """
function h(event, payload) {
  if (!ALLOWED.includes(payload.path)) return;
  fs.readFileSync(payload.path);
}
""", 'clean'),
    ('校验 name 却用 path（该报）', """
function h(event, payload) {
  if (payload.name !== 'ok') return;
  fs.readFileSync(payload.path);
}
""", 'danger'),
    ('解构赋值', """
function h(event, payload) {
  const { path: p } = payload;
  fs.readFileSync(p);
}
""", 'danger'),
    ('可选链', """
function h(event, payload) {
  fs.readFileSync(payload?.path);
}
""", 'danger'),
    ('reduce 累计器用到脏数组', """
function h(event, payload) {
  payload.list.reduce((acc, v) => fs.readFileSync(v), null);
}
""", 'danger'),
    ('setTimeout 里用了外层脏变量', """
function h(event, payload) {
  setTimeout(() => { fs.readFileSync(payload.path); }, 0);
}
""", 'danger'),
    ('事件回调里用了脏变量', """
function h(event, payload) {
  emitter.on('tick', () => fs.readFileSync(payload.path));
}
""", 'danger'),
    ('Set 白名单校验后使用', """
function h(event, payload) {
  if (!ALLOWED_SET.has(payload.path)) return;
  fs.readFileSync(payload.path);
}
""", 'clean'),
    ('正则校验后使用', """
function h(event, payload) {
  if (!/^\\/safe\\//.test(payload.path)) return;
  fs.readFileSync(payload.path);
}
""", 'clean'),
    ('空值合并右侧', """
function h(event, payload) {
  const p = payload.path ?? '/tmp/a';
  fs.readFileSync(p);
}
""", 'danger'),
    ('方括号取方法名', """
function h(event, payload) {
  fs['writeFileSync'](payload.path, 'x');
}
""", 'danger'),
    ('四层 helper 传下去', """
function h(event, payload) {
  a1(payload.path);
}
function a1(p) { a2(p); }
function a2(p) { a3(p); }
function a3(p) { fs.readFileSync(p); }
""", 'danger'),
    ('立即执行的函数传脏参', """
function h(event, payload) {
  (function (p) { fs.readFileSync(p); })(payload.path);
}
""", 'danger'),
    ('catch 里用错误对象读文件', """
function h(event, payload) {
  try { work(); } catch (err) { fs.readFileSync(err.path); }
}
""", 'unsupported'),
    ('数组下标取元素', """
function h(event, payload) {
  fs.readFileSync(payload.list[0]);
}
""", 'danger'),
    ('危险 API 起别名后调用（真包里抄的写法）', """
function h(event, payload) {
  const i = promisify(co.exec);
  return i(payload.cmd);
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
    ('已校验后再用（中和，不该报）', """
function h(event, payload) {
  if (payload.path !== '/safe') return;
  fs.readFileSync(payload.path);
}
""", 'clean'),
]


def analyse(source):
    """两种口径都跑：基名污点 + 字段敏感污点，取并集。

    为什么并集：字段敏感是更细的那一层，基名版会把「校验了 path」推广成
    「整个 payload 都干净」，反而漏报。两条都留着，谁抓到就报——宁可多报也不静默漏。
    """
    tokens = jsparse.tokenize(source)
    defs = jsparse.function_defs(tokens)
    hits = dict(jssem.interprocedural_hits(tokens, defs))
    for item in defs:
        field = jssem.field_hits(tokens, item['body_start'], item['body_end'],
                                 item['params'])
        if field and item['name'] not in hits:
            hits[item['name']] = field
    return hits


def main():
    caught = misses = false_alarms = known = broken = unsupported = 0
    failures = []
    failures_unsupported = []
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
        elif expect == 'unsupported':
            if reported:
                caught += 1
            else:
                unsupported += 1
                failures_unsupported.append(name)
        elif expect == 'known-gap':
            known += 1 if reported else 0
        else:
            if reported:
                false_alarms += 1
                failures.append((name, '不该报却报了'))

    danger = sum(1 for _n, _s, e in CASES if e in ('danger', 'unsupported'))
    clean = sum(1 for _n, _s, e in CASES if e == 'clean')
    print(f'正样本 {danger}：检出 {caught}，漏 {misses}，检出率 {caught / danger:.2f}')
    print(f'负样本 {clean}：误报 {false_alarms}，误报率 {false_alarms / clean:.2f}')
    print(f'已知缺口（会误报）：{known} 条，不计入误报')
    print(f'暂不支持（会漏，已知）：{unsupported} 条')
    for name in failures_unsupported:
        print(f'  · {name}：没报（已知不支持）')
    if broken:
        print(f'解析失败：{broken} 条')
    for name, why in failures:
        print(f'  · {name}：{why}')
    print('注：这几个片段是我自己写的，覆盖的是已支持的语言子集，不代表真实代码。')
    return 0 if not failures else 1


if __name__ == '__main__':
    raise SystemExit(main())
