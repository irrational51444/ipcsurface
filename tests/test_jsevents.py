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


class TerminalRenderTests(unittest.TestCase):
    """终端渲染：80 列、符号、以及最要紧的一条——借来档必须灰。"""

    DONE_PAYLOAD = {
        'stage': 'done', 'input': 'demo.asar', 'channels': 47, 'sinks': 116,
        'unresolved': 10,
        'by_tier': {'direct': 1, 'name_confirmed': 9, 'chain': 15,
                    'ambiguous': 41, 'ast_only': 50},
    }

    def make(self, use_color=True, width=80):
        r = jsevents.TerminalRenderer(stream=None, width=width, use_color=use_color)
        r.on_event({'kind': 'lifecycle', 'phase': 'coarse',
                    'payload': {'stage': 'start', 'input': 'demo.asar', 'size': 1048576}})
        return r

    def test_tier_glyph_colors(self):
        # 硬结论绿、同文件黄、借来灰——这是全局约定，不是渲染细节
        self.assertEqual(jsevents.tier_glyph('direct'), ('þ', '32'))
        self.assertEqual(jsevents.tier_glyph('name_confirmed'), ('þ', '32'))
        self.assertEqual(jsevents.tier_glyph('chain'), ('◐', '33'))
        self.assertEqual(jsevents.tier_glyph('ambiguous'), ('¨', '90'))
        self.assertEqual(jsevents.tier_glyph('ast_only'), ('¨', '90'))

    def test_unknown_tier_is_grey_not_green(self):
        glyph, code = jsevents.tier_glyph('whatever')
        self.assertEqual(code, '90', '不认识的档位必须给灰的，不许借绿')

    def test_borrowed_tiers_never_use_red_or_yellow(self):
        r = self.make()
        r.on_event({'kind': 'lifecycle', 'phase': 'report',
                    'payload': self.DONE_PAYLOAD})
        text = r.render()
        bad = [line for line in text.splitlines()
               if '借来' in line
               and any(code in line for code in ('\033[31m', '\033[33m', '\033[91m'))]
        self.assertFalse(bad, '借来档不许用红/黄：%r' % (bad,))

    def test_done_line_carries_the_three_numbers(self):
        r = self.make()
        r.on_event({'kind': 'lifecycle', 'phase': 'report',
                    'payload': self.DONE_PAYLOAD})
        text = r.render()
        self.assertIn('47 channels', text)
        self.assertIn('116 sinks', text)
        self.assertIn('10 unresolved', text)

    def test_width_is_respected(self):
        r = self.make(width=60)
        r.on_event({'kind': 'discovery', 'phase': 'coarse',
                    'payload': {'name': 'a' * 200, 'tier': None}})
        text = r.render()
        longest = max(len(line) for line in text.splitlines())
        self.assertLessEqual(longest, 60, '每一行都不许超过 width')

    def test_progress_line_shows_files_and_rate(self):
        r = self.make()
        r.on_event({'kind': 'progress', 'phase': 'coarse',
                    'payload': {'files_done': 300, 'files_total': 369,
                                'elapsed_ms': 3209}})
        text = r.render()
        self.assertIn('files 300/369', text)
        self.assertIn('MB/s', text)


class EventServerTests(unittest.TestCase):
    """P3：单页 + SSE + 快照。起真服务器，打真 HTTP。"""

    def setUp(self):
        import threading  # noqa: F401 —— 让 EventServer 内部的线程能跑
        self.bus = jsevents.EventBus(None)
        self.server = jsevents.EventServer(self.bus, host='127.0.0.1', port=0)
        self.server.start()
        self.base = 'http://127.0.0.1:%d' % self.server.port

    def tearDown(self):
        self.server.stop()

    def get(self, path):
        import urllib.request
        with urllib.request.urlopen(self.base + path, timeout=5) as resp:
            return resp.status, resp.read().decode('utf-8', 'replace')

    def test_page_is_self_contained(self):
        status, html = self.get('/')
        self.assertEqual(status, 200)
        self.assertIn('ipcsurface live', html)
        # 零 CDN：页面里不许出现 http(s):// 的外链脚本
        self.assertNotIn('src="http', html)
        self.assertNotIn('https://', html)

    def test_snapshot_reflects_events(self):
        self.bus.emit('lifecycle', {'stage': 'start', 'input': 'x.asar'})
        self.bus.emit('discovery', {'name': 'a:b', 'tier': None})
        self.bus.emit('discovery', {'name': 'c:d', 'tier': 'direct'})
        status, body = self.get('/api/snapshot')
        self.assertEqual(status, 200)
        snap = json.loads(body)
        self.assertEqual(snap['input'], 'x.asar')
        self.assertEqual(snap['channels'], ['a:b', 'c:d'])
        self.assertEqual(snap['tiers']['c:d'], 'direct')

    def test_snapshot_carries_done(self):
        self.bus.emit('lifecycle', {'stage': 'done', 'channels': 3, 'sinks': 5,
                                    'unresolved': 1, 'by_tier': {'direct': 3}})
        _, body = self.get('/api/snapshot')
        self.assertEqual(json.loads(body)['done']['channels'], 3)

    def test_snapshot_reads_channel_tiers_from_done(self):
        """discovery 当时的 tier 是 None，扫完 done 才定；快照要拿 done 里那份。"""
        self.bus.emit('discovery', {'name': 'a:b', 'tier': None})
        self.bus.emit('discovery', {'name': 'c:d', 'tier': None})
        self.bus.emit('lifecycle', {'stage': 'done', 'channels': 2, 'sinks': 2,
                                    'unresolved': 0, 'by_tier': {'direct': 1, 'chain': 1},
                                    'channel_tiers': {'a:b': 'direct', 'c:d': 'chain'}})
        _, body = self.get('/api/snapshot')
        snap = json.loads(body)
        self.assertEqual(snap['tiers']['a:b'], 'direct')
        self.assertEqual(snap['tiers']['c:d'], 'chain')
        # 通道不许因为 done 里再出现一次就重复
        self.assertEqual(snap['channels'], ['a:b', 'c:d'])

    def test_export_is_jsonl(self):
        self.bus.emit('lifecycle', {'stage': 'start', 'input': 'y.asar'})
        _, body = self.get('/api/export')
        lines = [line for line in body.splitlines() if line.strip()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])['kind'], 'lifecycle')

    def test_unknown_path_is_404(self):
        import urllib.error
        import urllib.request
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self.base + '/nope', timeout=5)
        self.assertEqual(ctx.exception.code, 404)

    def test_zero_buffer_keeps_nothing_in_memory(self):
        """--max-buffer 0：页面照常推送，但一条都不留在内存里。"""
        bus = jsevents.EventBus(None)
        server = jsevents.EventServer(bus, port=0, max_events=0).start()
        try:
            bus.emit('discovery', {'name': 'a:b', 'tier': None})
            bus.emit('lifecycle', {'stage': 'done', 'channels': 1, 'sinks': 0,
                                   'unresolved': 0, 'by_tier': {}})
            self.assertEqual(server.state.events, [], '不该留任何事件')
            snap = server.state.snapshot()
            self.assertEqual(snap['channels'], [], '快照也不该有东西')
        finally:
            server.stop()

    def test_default_buffer_keeps_events(self):
        bus = jsevents.EventBus(None)
        server = jsevents.EventServer(bus, port=0).start()
        try:
            bus.emit('discovery', {'name': 'c:d', 'tier': None})
            self.assertEqual(len(server.state.events), 1)
        finally:
            server.stop()

    def test_sse_replays_history_after_last_event_id(self):
        """断线重连：带 Last-Event-ID 只补发之后的事件。"""
        import socket
        for i in range(3):
            self.bus.emit('discovery', {'name': 'ch%d' % i})
        host, port = '127.0.0.1', self.server.port
        sock = socket.create_connection((host, port), timeout=5)
        try:
            sock.sendall(b'GET /events HTTP/1.1\r\nHost: x\r\n'
                         b'Last-Event-ID: 2\r\nAccept: text/event-stream\r\n\r\n')
            # 头和事件体可能是两次 write，要循环读到有正文为止
            buf = b''
            for _ in range(20):
                part = sock.recv(4096)
                if not part:
                    break
                buf += part
                if b'id: ' in buf:
                    break
            chunk = buf.decode('utf-8', 'replace')
        finally:
            sock.close()
        # 只应该看到 seq 3，不该重放 1 和 2
        self.assertIn('id: 3', chunk)
        self.assertNotIn('id: 1', chunk)
        self.assertNotIn('id: 2', chunk)


FIXTURES = os.path.join(ROOT, 'tests', 'fixtures', 'events')


class ReplayTests(unittest.TestCase):
    """P5：回放必须和当初录的那条流一模一样——seq 不许重排。"""

    def path(self, name):
        p = os.path.join(FIXTURES, name)
        if not os.path.exists(p):
            self.skipTest('fixture 不存在：' + name)
        return p

    def test_replay_keeps_seq_and_order(self):
        p = self.path('normal.jsonl')
        expected = jsevents.load_events(p)
        got = []
        bus = jsevents.EventBus(None)
        bus.add_listener(got.append)
        sent = jsevents.replay(p, bus, speed=0)
        self.assertEqual(sent, len(expected))
        self.assertEqual([e['seq'] for e in got], [e['seq'] for e in expected])
        self.assertEqual([e['kind'] for e in got], [e['kind'] for e in expected])

    def test_replay_drives_snapshot(self):
        p = self.path('warnings.jsonl')
        bus = jsevents.EventBus(None)
        server = jsevents.EventServer(bus, port=0).start()
        try:
            jsevents.replay(p, bus, speed=0)
            snap = server.state.snapshot()
            self.assertTrue(snap['channels'], '回放后应该有通道')
            self.assertTrue(snap['warnings'], 'warnings fixture 里应该有预警')
        finally:
            server.stop()

    def test_crash_fixture_has_no_done(self):
        p = self.path('crash.jsonl')
        events = jsevents.load_events(p)
        done = [e for e in events
                if e['kind'] == 'lifecycle' and e['payload'].get('stage') == 'done']
        self.assertFalse(done, 'crash fixture 不该有 done')

    def test_replay_of_empty_file_returns_zero(self):
        import tempfile
        path = tempfile.mktemp(suffix='.jsonl')
        open(path, 'w').close()
        try:
            bus = jsevents.EventBus(None)
            self.assertEqual(jsevents.replay(path, bus, speed=0), 0)
        finally:
            os.unlink(path)


class ReconcileEndToEndTests(unittest.TestCase):
    """P5：跑一次真扫描，事件流末条统计必须和报告 JSON 逐项相等（守则 4）。"""

    def test_cli_events_match_cli_report(self):
        import subprocess
        import tempfile
        asar = os.path.join(ROOT, 'examples', 'build', 'static-asar.asar')
        if not os.path.exists(asar):
            self.skipTest('靶场没构建')
        ev = tempfile.mktemp(suffix='.jsonl')
        rp = tempfile.mktemp(suffix='.json')
        try:
            run = subprocess.run(
                [sys.executable, os.path.join(ROOT, 'ipcsurface.py'),
                 asar, '--format', 'json', '-o', rp, '--events-out', ev],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding='utf-8', errors='replace', timeout=180)
            self.assertEqual(run.returncode, 0, (run.stderr or '')[-400:])
            with open(rp, encoding='utf-8') as fh:
                report = json.load(fh)
            problems = jsevents.diff_summary(ev, report)
            self.assertEqual(problems, [], '事件流和报告对不上：%r' % (problems,))
        finally:
            for path in (ev, rp):
                try:
                    os.unlink(path)
                except OSError:
                    pass

    def test_no_events_flag_leaves_output_identical(self):
        """同一份输入跑两次（都不带 --events-out），输出必须字节级一致。

        这条挡的是「加了实时功能之后悄悄改了默认输出」——设计约束第 5 条。
        """
        import subprocess
        import tempfile
        asar = os.path.join(ROOT, 'examples', 'build', 'static-asar.asar')
        if not os.path.exists(asar):
            self.skipTest('靶场没构建')
        a = tempfile.mktemp(suffix='.json')
        b = tempfile.mktemp(suffix='.json')
        try:
            for out in (a, b):
                subprocess.run([sys.executable, os.path.join(ROOT, 'ipcsurface.py'),
                                asar, '--format', 'json', '-o', out],
                               capture_output=True, timeout=180)
            with open(a, 'rb') as fh:
                first = fh.read()
            with open(b, 'rb') as fh:
                second = fh.read()
            self.assertEqual(first, second, '同一输入跑两次，输出该字节级一致')
        finally:
            for path in (a, b):
                try:
                    os.unlink(path)
                except OSError:
                    pass


if __name__ == '__main__':
    unittest.main()
