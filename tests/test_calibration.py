"""校准脚本的用例：sink 路径强度档的分类逻辑。

sink_tier 的正式定义在 jsreport.py（报告层），calibration 只是 import 它。
这里直接测 jsreport 里的那个，别走 calibration 的中转，免得中间断了没人发现。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, ROOT)

from jsreport import SINK_TIER_ORDER, sink_tier  # noqa: E402


def facts(paths=None, sinks=None, ambiguous=()):
    return {
        'channel_sink_paths': paths or {},
        'channel_sinks': sinks or {},
        'channel_sinks_ambiguous': list(ambiguous),
    }


class SinkTierTests(unittest.TestCase):
    def test_direct_call(self):
        f = facts(
            paths={'a': {'writeFileSync': {'hops': 1, 'via': ''}}},
            sinks={'a': ['writeFileSync']},
        )
        self.assertEqual(sink_tier(f, 'a', 'writeFileSync'), 'direct')

    def test_chain_through_function(self):
        f = facts(
            paths={'a': {'writeFileSync': {'hops': 2, 'via': '_→ae'}}},
            sinks={'a': ['writeFileSync']},
        )
        self.assertEqual(sink_tier(f, 'a', 'writeFileSync'), 'chain')

    def test_ambiguous_via_marker(self):
        f = facts(
            paths={'a': {'rmSync': {'hops': 2, 'via': 'kt→f（同名多义）'}}},
            sinks={'a': ['rmSync']},
        )
        self.assertEqual(sink_tier(f, 'a', 'rmSync'), 'ambiguous')

    def test_ambiguous_by_channel_flag(self):
        # 通道进了 ambiguous 名单，即使这条 API 自己的 via 没带标记也算 ambiguous
        f = facts(
            paths={'a': {'rmSync': {'hops': 1, 'via': 'f'}}},
            sinks={'a': ['rmSync']},
            ambiguous=['a'],
        )
        self.assertEqual(sink_tier(f, 'a', 'rmSync'), 'ambiguous')

    def test_name_confirmed_when_both_engines_report(self):
        # AST 报了、名字级也报，但路径没记录（别名/成员调用）
        f = facts(sinks={'a': ['request']})
        self.assertEqual(sink_tier(f, 'a', 'request'), 'name_confirmed')

    def test_ast_only_when_names_miss(self):
        # 只有语法树口径连上，名字级没连上——最可疑
        f = facts(sinks={'a': ['copyFileSync']})
        self.assertEqual(sink_tier(f, 'a', 'exec'), 'ast_only')

    def test_order_is_high_to_low(self):
        # 档位顺序就是单调性断言的依据，顺序不能乱
        self.assertEqual(
            SINK_TIER_ORDER,
            ['direct', 'name_confirmed', 'chain', 'ambiguous', 'ast_only'])


if __name__ == '__main__':
    unittest.main()
