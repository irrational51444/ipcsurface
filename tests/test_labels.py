"""jslabels（标签层）与 native_imports（PE 导入表面）的用例。

这两个模块小、以前没直接测，覆盖率低。补上：danger_kind_of 的每一类、
stamp 的两个分支、native_import_surface 的跳过 / 异常路径。
"""
import unittest

import jslabels
import native_imports


class LabelsTests(unittest.TestCase):
    def test_danger_kind_map_covers_every_category(self):
        cases = {
            'writeFile': '文件写',
            'readFileSync': '文件读',
            'exec': '命令执行',
            'fetch': '网络',
            'eval': '动态求值',
            'no_such_api': '其它',
        }
        for api, kind in cases.items():
            self.assertEqual(jslabels.danger_kind_of(api), kind, api)

    def test_stamp_with_and_without_version(self):
        self.assertIn('ipcsurface 0.85.0', jslabels.stamp('0.85.0'))
        self.assertNotIn('ipcsurface', jslabels.stamp(None))


class NativeImportsTests(unittest.TestCase):
    def test_ignores_non_native_files(self):
        # 普通 js 不是 .node/.dll，直接跳过
        self.assertEqual(native_imports.native_import_surface({'a.js': b'x'}), {})

    def test_skips_none_payload(self):
        self.assertEqual(native_imports.native_import_surface({'x.node': None}), {})

    def test_skips_non_mz(self):
        # 加壳的 .node 开头不是 MZ，读不到，返回空（「读不到」不是「没有」）
        self.assertEqual(native_imports.native_import_surface({'x.node': b'not a pe'}), {})

    def test_skips_broken_pe(self):
        # MZ 头但不是合法 PE（parse_pe_bytes 抛 SystemExit），不崩，返回空
        self.assertEqual(
            native_imports.native_import_surface({'x.node': b'MZ' + b'\0' * 200}), {})


if __name__ == '__main__':
    unittest.main()
