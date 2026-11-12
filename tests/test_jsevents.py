"""jsevents 的用例：信封、队列、分级丢弃、对账。"""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import jsevents  # noqa: E402


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.path = os.path.join(self.folder, 'ev.jsonl')

    def tearDown(self):
        try:
            os.unlink(self.path)
        except OSError:
            pass

    def read(self):
        with open(self.path, encoding='utf-8') as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def test_envelope_has_required_fields(self):
        bus = jsevents.EventBus(self.path, scan_id='sha256:abc')
        bus.emit('lifecycle', {'stage': 'start'})
        bus.close()
        ev = self.read()[0]
        for key in ('schema', 'seq', 'ts', 'scan_id', 'phase', 'kind', 'payload'):
            self.assertIn(key, ev)
        self.assertEqual(ev['schema'], 'ipcsurface/event/1')
        self.assertEqual(ev['scan_id'], 'sha256:abc')
        self.assertEqual(ev['seq'], 1)

    def test_seq_is_monotonic(self):
        bus = jsevents.EventBus(self.path)
        for i in range(5):
            bus.emit('discovery', {'name': 'c%d' % i})
        bus.close()
        seqs = [e['seq'] for e in self.read()]
        self.assertEqual(seqs, [1, 2, 3, 4, 5])

    def test_unknown_kind_is_rejected(self):
        bus = jsevents.EventBus(self.path)
        with self.assertRaises(ValueError):
            bus.emit('nope', {})
        bus.close()

    def test_unknown_phase_is_rejected(self):
        bus = jsevents.EventBus(self.path)
        with self.assertRaises(ValueError):
            bus.emit('lifecycle', {}, phase='nowhere')
        bus.close()

    def test_progress_is_droppable_other_kinds_are_not(self):
        # 队列塞满时，progress 可以丢；discovery 必须挤掉一条 progress 也要留下。
        # 这里用 assertEqual 而不是 assertTrue：后者在这种布尔返回值上会被
        # 元测试判成 vacuous，逼着把「到底期望 True 还是 False」写明白。
        bus = jsevents.EventBus(self.path, max_queue=2, flush_every=10 ** 6,
                                flush_interval=10 ** 6)
        self.assertEqual(bus.emit('progress', {'i': 0}), True, '第一条应当接收')
        self.assertEqual(bus.emit('progress', {'i': 1}), True, '第二条应当接收')
        self.assertEqual(bus.emit('progress', {'i': 2}), False,
                         '队列满了应拒收 progress')
        self.assertEqual(bus.emit('discovery', {'name': 'x'}), True,
                         '不可丢事件应挤掉一条 progress 腾位置')
        bus.close()
        kinds = [e['kind'] for e in self.read()]
        self.assertIn('discovery', kinds)

    def test_dropped_counter_tracks_rejections(self):
        bus = jsevents.EventBus(self.path, max_queue=1, flush_every=10 ** 6,
                                flush_interval=10 ** 6)
        bus.emit('progress', {'i': 0})
        bus.emit('progress', {'i': 1})
        stats = bus.stats()
        self.assertEqual(stats['dropped'], 1)
        bus.close()

    def test_close_flushes_remaining(self):
        bus = jsevents.EventBus(self.path, flush_every=10 ** 6, flush_interval=10 ** 6)
        bus.emit('warning', {'id': 'w1'})
        self.assertEqual(os.path.getsize(self.path), 0, '批量阈值没到不该落盘')
        bus.close()
        self.assertEqual(len(self.read()), 1)


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.path = os.path.join(self.folder, 'ev.jsonl')
        self.report = {
            'channels': ['a', 'b'],
            'channel_sinks_ast': {'a': ['writeFile'], 'b': ['exec']},
            'channel_sink_tiers': {'a': {'writeFile': 'direct'}, 'b': {'exec': 'chain'}},
            'dynamic': [],
        }

    def tearDown(self):
        try:
            os.unlink(self.path)
        except OSError:
            pass

    def write_done(self, payload):
        bus = jsevents.EventBus(self.path)
        bus.emit('lifecycle', payload, phase='report')
        bus.close()

    def test_report_summary_matches_done_payload(self):
        self.write_done({
            'stage': 'done', 'channels': 2, 'sinks': 2,
            'by_tier': {'direct': 1, 'chain': 1}, 'unresolved': 0,
        })
        self.assertEqual(jsevents.diff_summary(self.path, self.report), [])

    def test_mismatch_is_reported(self):
        self.write_done({
            'stage': 'done', 'channels': 3, 'sinks': 2,
            'by_tier': {'direct': 1, 'chain': 1}, 'unresolved': 0,
        })
        problems = jsevents.diff_summary(self.path, self.report)
        self.assertTrue(any('channels' in p for p in problems), problems)

    def test_missing_last_event_is_reported(self):
        self.assertEqual(jsevents.diff_summary(self.path, self.report),
                         ['事件流是空的，没法对账'])

    def test_last_event_must_be_done(self):
        bus = jsevents.EventBus(self.path)
        bus.emit('stats', {'channels': 2})
        bus.close()
        problems = jsevents.diff_summary(self.path, self.report)
        self.assertTrue(problems)
        self.assertIn('lifecycle.done', problems[0])


if __name__ == '__main__':
    unittest.main()
