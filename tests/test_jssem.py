"""jssem / jsparse 的用例：每一类形状一个，答案写在断言里。

这些用例只覆盖已声明的语言子集：不支持的形状写在这行之外，
不假装能分析——报告里出现的「未分析」也是结论，不是回避。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import jssem  # noqa: E402
import jsparse  # noqa: E402


def hits_of(source):
    tokens = jsparse.tokenize(source)
    item = jsparse.function_defs(tokens)[0]
    return jssem.field_hits(tokens, item['body_start'], item['body_end'], item['params'])


class FlowTests(unittest.TestCase):
    def test_direct_param_into_sink(self):
        self.assertTrue(hits_of('function h(e, p) { fs.readFileSync(p); }'))

    def test_through_local_variable(self):
        src = 'function h(e, p) { const a = p.path; fs.readFileSync(a); }'
        self.assertTrue(hits_of(src))

    def test_template_literal(self):
        src = 'function h(e, p) { const c = `ls ${p.dir}`; execSync(c); }'
        self.assertTrue(hits_of(src))

    def test_logical_or_rhs(self):
        src = 'function h(e, p) { const a = p.x || "/tmp"; fs.readFileSync(a); }'
        self.assertTrue(hits_of(src))

    def test_destructuring(self):
        src = 'function h(e, p) { const { path: q } = p; fs.readFileSync(q); }'
        self.assertTrue(hits_of(src))

    def test_optional_chain(self):
        self.assertTrue(hits_of('function h(e, p) { fs.readFileSync(p?.path); }'))

    def test_for_of_loop_var(self):
        src = ('function h(e, p) { for (const item of p.list) '
               '{ fs.readFileSync(item); } }')
        self.assertTrue(hits_of(src))

    def test_constant_path_is_clean(self):
        self.assertFalse(hits_of('function h(e) { fs.readFileSync("/etc/hostname"); }'))

    def test_regex_exec_is_clean(self):
        src = 'function h(e, t) { const re = /a(b)c/; return re.exec(t); }'
        self.assertFalse(hits_of(src))


class NeutralisationTests(unittest.TestCase):
    def test_literal_guard_cleans_field(self):
        src = ('function h(e, p) { if (p.path !== "/safe") return; '
               'fs.readFileSync(p.path); }')
        self.assertFalse(hits_of(src))

    def test_guard_on_one_field_does_not_clean_another(self):
        src = ('function h(e, p) { if (p.name !== "ok") return; '
               'fs.readFileSync(p.path); }')
        self.assertTrue(hits_of(src))

    def test_negated_validator_call_cleans(self):
        src = ('function h(e, p) { if (!isSafe(p.path)) return; '
               'fs.readFileSync(p.path); }')
        self.assertFalse(hits_of(src))

    def test_negated_includes_cleans(self):
        src = ('function h(e, p) { if (!ALLOWED.includes(p.path)) return; '
               'fs.readFileSync(p.path); }')
        self.assertFalse(hits_of(src))


class CrossFileTests(unittest.TestCase):
    FILES = {
        'src/main.js': "const svc = require('./svc');\n"
                       "function h(e, p) { return svc.read(p.path); }\n",
        'src/svc.js': "module.exports = { read(p) { return fs.readFileSync(p); } };\n",
    }

    def test_relative_require_resolves(self):
        tokens = jsparse.tokenize(self.FILES['src/main.js'])
        targets = jssem.cross_file_targets(tokens, 'src/main.js', set(self.FILES))
        self.assertEqual(list(targets.values()), ['src/svc.js'])

    def test_member_call_reaches_other_file_sink(self):
        tokens = {rel: jsparse.tokenize(text) for rel, text in self.FILES.items()}
        main = tokens['src/main.js']
        found = jssem.cross_file_member_sinks(main, 0, len(main), 'src/main.js', tokens)
        self.assertEqual(found[0][0], 'src/svc.js')
        self.assertEqual(found[0][1], 'read')
        self.assertIn('readFileSync', found[0][2])

    def test_package_import_is_not_followed(self):
        tokens = jsparse.tokenize("const fs = require('fs');")
        targets = jssem.cross_file_targets(tokens, 'src/main.js', set(self.FILES))
        self.assertEqual(targets, {})

    def test_two_hops_across_files(self):
        """main → svc → util，真正碰文件的在第二跳，必须跟到。"""
        files = {
            'src/main.js': "const svc = require('./svc');\n"
                           "function h(e, p) { return svc.read(p.path); }\n",
            'src/svc.js': "const util = require('./util');\n"
                          "module.exports = { read(p) { return util.load(p); } };\n",
            'src/util.js': "module.exports = { load(p) { return fs.readFileSync(p); } };\n",
        }
        tokens = {rel: jsparse.tokenize(text) for rel, text in files.items()}
        main = tokens['src/main.js']
        found = jssem.cross_file_member_sinks(main, 0, len(main), 'src/main.js', tokens)
        self.assertIn('src/util.js', [item[0] for item in found])


if __name__ == '__main__':
    unittest.main()
