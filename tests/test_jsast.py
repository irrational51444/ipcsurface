"""语法树引擎的用例：成员调用、方括号方法名、别名、回调传递。"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import jsast  # noqa: E402
import jssem  # noqa: E402


def reaches(code, roots):
    program = jsast.parse(code)
    return jsast.reachable_danger(program, roots, jssem.DANGER)


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
