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

    def test_borrowed_tiers_exist_and_are_worse(self):
        """软档必须还在，而且必须明显差于硬结论——两件事一起守。

        0.97.0 曾把软档整块砍掉换取 100% 精确率，但那是拿漏报换数字：
        砍掉的 9 条里有真阳性。所以这条测试同时守住：
        1. 软档存在（不砍，不靠藏东西抬数字）
        2. 软档确实比硬结论差（分层有效，不是贴着硬档）
        """
        hard = min(self.data['tiers_chan'][t]['precision']
                   for t in ('direct', 'name_confirmed', 'chain'))
        for tier in ('ambiguous', 'ast_only'):
            item = self.data['tiers_chan'][tier]
            self.assertIsNotNone(item['precision'],
                                 '%s 档被砍掉了，这就是漏报' % tier)
            self.assertLess(item['precision'], hard - 0.3,
                            '%s 档 %.2f 没比硬结论低多少，分层失效'
                            % (tier, item['precision']))


if __name__ == '__main__':
    unittest.main()
