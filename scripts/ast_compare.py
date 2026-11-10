"""把尺子上的用例同时喂给两个引擎，看语法树版比粗扫版多认到什么、少认掉什么。

用法：python scripts/ast_compare.py
"""
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import jsast  # noqa: E402
import jssem  # noqa: E402
import jsparse  # noqa: E402

spec = importlib.util.spec_from_file_location(
    'ruler', os.path.join(ROOT, 'scripts', 'taint_ruler.py'))
ruler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ruler)


def ast_calls(code):
    program = jsast.parse(code)
    names = []
    for node in jsast.walk(program):
        if node.kind == 'Function':
            continue
        pass
    # 顶层与所有函数里的危险调用
    found = set()
    for node in jsast.walk(program):
        if node.kind != 'Call' or not node.children:
            continue
        callee = node.children[0]
        if callee.kind == 'Ident' and callee.value in jssem.DANGER:
            found.add(callee.value)
        elif callee.kind == 'Member' and callee.value in jssem.DANGER:
            found.add(callee.value)
    del names
    return found


def ast_reachable(code):
    """从所有顶层函数出发做可达性。"""
    program = jsast.parse(code)
    tops = [node for node in program.children if node.kind == 'Function']
    roots = [(node.value or {}).get('name') for node in tops]
    roots = [name for name in roots if name]
    found, _paths = [], []
    for root in roots:
        result = jsast.reachable_danger(program, [root], jssem.DANGER)
        for api in result:
            if api not in found:
                found.append(api)
    return found


def main():
    cases = getattr(ruler, 'POSITIVES', None) or getattr(ruler, 'CASES', [])
    rows = []
    for item in cases:
        name, code = item[0], item[1]
        expect = item[2] if len(item) > 2 else 'danger'
        direct = ast_calls(code)
        reach = ast_reachable(code)
        rows.append((name, expect, sorted(direct), sorted(reach)))
    print('%-34s %-8s %-22s %s' % ('用例', '期望', '树-直接', '树-可达'))
    for name, expect, direct, reach in rows:
        mark = 'ok' if (bool(reach) == (expect == 'danger')) else '≠'
        print('%-34s %-8s %-22s %s %s' % (name[:34], expect, ','.join(direct) or '-',
                                           ','.join(reach) or '-', mark))
    # 口径说明：树版回答的是「能不能碰到危险调用」，不是「脏不脏」。
    # clean 用例里出现 readFileSync 是对的——调用在那儿，只是参数被中和过；
    # 判干净是污点引擎的活。所以这里只按 danger 用例算命中。
    danger_rows = [r for r in rows if r[1] == 'danger']
    hit = sum(1 for _n, _e, _d, reach in danger_rows if reach)
    clean_with_api = sum(1 for _n, e, _d, reach in rows if e == 'clean' and reach)
    print('\n可达性：%d 条 danger 用例里认出 %d 条' % (len(danger_rows), hit))
    print('另有 %d 条 clean 用例也能碰到危险调用——这是可达性该有的答案，判干净归污点引擎'
          % clean_with_api)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
