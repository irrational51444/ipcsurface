"""校准脚本与基线的护栏。

加这个是因为真踩过：重写文件尾部时把 `if __name__ == '__main__':` 删掉了，
脚本跑起来**什么都不做、也不报错**，退出码 0——静默失败最难发现。
"""
import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'scripts', 'calibration.py')
BASELINE = os.path.join(ROOT, 'tests', 'golden', 'calibration.json')


class CalibrationScriptTests(unittest.TestCase):
    def test_script_has_main_guard(self):
        with open(SCRIPT, encoding='utf-8') as fh:
            text = fh.read()
        self.assertIn("if __name__ == '__main__':", text,
                      '没有入口，脚本跑起来会静默什么都不做')

    def test_script_accepts_baseline_flags(self):
        with open(SCRIPT, encoding='utf-8') as fh:
            text = fh.read()
        self.assertIn('--baseline', text)
        self.assertIn('--write-baseline', text)
        # 容差必须是个显式的可调参数，不许写死在比较里
        self.assertIn('--tolerance', text)


class BaselineFileTests(unittest.TestCase):
    def setUp(self):
        if not os.path.exists(BASELINE):
            self.skipTest('基线还没生成')
        with open(BASELINE, encoding='utf-8') as fh:
            self.data = json.load(fh)

    def test_schema_and_shape(self):
        self.assertEqual(self.data['schema'], 'ipcsurface/calibration/2')
        self.assertIn('tiers', self.data)
        self.assertIn('tiers_chan', self.data)

    def test_hard_tiers_are_perfect(self):
        """直连 / 双口径 / 同文件链三档必须 100%——掉下来就是代码坏了。"""
        for tier in ('direct', 'name_confirmed', 'chain'):
            item = self.data['tiers_chan'][tier]
            self.assertEqual(item['fp'], 0, '%s 档不该有误报' % tier)
            self.assertEqual(item['precision'], 1.0, '%s 档应该是 100%%' % tier)

    def test_borrowed_tiers_have_no_conclusions(self):
        """软档不再产出结论：baseline 里这两档应该**没有**精确率。

        0.97.0 起，ambiguous / ast_only 报出来的 API 挪进了 channel_sinks_borrowed，
        不参与结论。它们要是又出现在精度表里，说明过滤被绕过去了。
        """
        for tier in ('ambiguous', 'ast_only'):
            item = self.data['tiers_chan'][tier]
            self.assertIsNone(item['precision'],
                              '%s 档不该再有精确率——它已经不产结论了' % tier)


if __name__ == '__main__':
    unittest.main()
