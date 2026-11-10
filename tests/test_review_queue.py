"""复核队列的用例：按链路归堆，别按通道数吓人。"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, ROOT)

import review_queue as rq  # noqa: E402


class QueueTests(unittest.TestCase):
    def rows(self):
        return [
            {'channel': 'a', 'apis': ['writeFileSync'], 'hops': 2, 'via': '_→ae',
             'tier': 3, 'tainted': False},
            {'channel': 'b', 'apis': ['writeFileSync'], 'hops': 2, 'via': '_→ae',
             'tier': 3, 'tainted': False},
            {'channel': 'c', 'apis': ['exec'], 'hops': 1, 'via': '',
             'tier': 2, 'tainted': False},
        ]

    def test_same_chain_collapses(self):
        groups = rq.group_by_chain(self.rows())
        self.assertEqual(len(groups), 2, '两条通道同一条链路应当合成一堆')
        self.assertEqual(len(groups['_→ae']['channels']), 2)

    def test_direct_call_is_its_own_bucket(self):
        groups = rq.group_by_chain(self.rows())
        self.assertIn('（处理函数自己调的）', groups)

    def test_tier_prefers_tainted(self):
        facts = {
            'channel_sinks': {'x': ['renameSync'], 'y': ['writeFileSync']},
            'channel_sink_paths': {
                'x': {'renameSync': {'hops': 2, 'via': 'a→b'}},
                'y': {'writeFileSync': {'hops': 1, 'via': ''}},
            },
            'channel_tainted': {'x': [('renameSync', 'p', 1)]},
        }
        rows = rq.build_queue(facts, 5)
        self.assertEqual(rows[0]['channel'], 'x', '污点命中的排最前')


if __name__ == '__main__':
    unittest.main()
