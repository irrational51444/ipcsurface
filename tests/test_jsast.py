"""语法树引擎的用例：成员调用、方括号方法名、别名、回调传递。"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import jsast  # noqa: E402
import jsparse  # noqa: E402
import jssem  # noqa: E402


def reaches(code, roots):
    program = jsast.parse(code)
    return jsast.reachable_danger(program, roots, jssem.DANGER)


class ParserRegressionTests(unittest.TestCase):
    """这三条是真包里撞出来的 bug，修完必须有人盯着别退回去。"""

    def others(self, code):
        program = jsast.parse(code)
        return [n.value for n in jsast.walk(program) if n.kind == 'Other']

    def test_comma_expression(self):
        code = 'function f(a){ return a, a + 1, a + 2; }'
        self.assertEqual(self.others(code), [],
                         'return 里的逗号表达式不该留下未知节点')

    def test_regex_class_with_semicolon(self):
        code = "function g(e){ if (/^data:([\\w+-]+\\/[\\w+.-]+)?[,;]/.test(e)) return 1; }"
        program = jsast.parse(code)
        self.assertEqual([n.value for n in jsast.walk(program) if n.kind == 'Other'], [])
        regexes = [tok for tok in jsparse.tokenize(code) if tok.kind == 'regex']
        self.assertTrue(regexes, '带 [,;] 的正则要被当成正则，不是除号')

    def test_for_header_declaration_and_postfix(self):
        code = 'function h(){ for (var i = 0, n = 2; i < n; i++) { i; } }'
        self.assertEqual(self.others(code), [],
                         'for 头部的多声明 + 后缀自增不该留下未知节点')

    def test_private_field_and_optional_call(self):
        code = 'class A { #x = 1; get() { return this.#x; } }'
        self.assertEqual(self.others(code), [], '私有字段 #x 不该漏成未知节点')
        code2 = 'function f(t) { return t?.split?.(";")[0]; }'
        self.assertEqual(self.others(code2), [], '可选调用 ?.() 不该漏成未知节点')

    def test_danger_still_found_after_fixes(self):
        code = ('function save(){fs.writeFileSync("a","b");}\n'
                'function h(e){ for (var i=0,n=1;i<n;i++) { save(); } }')
        self.assertIn('writeFileSync', reaches(code, ['h']))


class AstReachTests(unittest.TestCase):
    def test_simple_call_chain(self):
        code = "function save(){fs.writeFileSync('a','b');}\nfunction h(e){save();}"
        self.assertIn('writeFileSync', reaches(code, ['h']))

    def test_member_call_matches_method_name(self):
        code = "function h(e){const t={flush(){fs.writeFileSync('x','y')}};t.flush();}"
        self.assertIn('writeFileSync', reaches(code, ['h']),
                      '成员调用 t.flush() 应当连到 flush 的方法定义')

    def test_bracket_member(self):
        code = "function h(e,p){fs['readFileSync'](p.path);}"
        self.assertIn('readFileSync', reaches(code, ['h']))

    def test_const_alias(self):
        code = ("function h(e,p){const run=require('child_process').exec;"
                "run(p.cmd);}")
        self.assertIn('exec', reaches(code, ['h']))

    def test_callback_argument_is_an_edge(self):
        code = "function save(){fs.writeFileSync('a','b');}\nfunction h(e){[1].map(save);}"
        self.assertIn('writeFileSync', reaches(code, ['h']),
                      '把函数名当回调传，也是调用边')

    def test_unknown_name_does_not_guess(self):
        code = "function h(e){mystery();}"
        self.assertEqual(reaches(code, ['h']), {})

    def test_local_shadow_blocks_member_guess(self):
        code = ("function h(e){const t={};t.flush();}\n"
                "function flush(){fs.writeFileSync('a','b');}")
        self.assertEqual(reaches(code, ['h']), {},
                         't.flush 是对象自己的方法，不该连到全局 flush')


if __name__ == '__main__':
    unittest.main()
