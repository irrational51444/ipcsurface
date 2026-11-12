"""attach 探测脚本的帧逻辑用例：不连真进程，只验 WebSocket 帧和 JSON 往返。"""
import json
import os
import socket
import sys
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, ROOT)

import probe_attach as pa  # noqa: E402


class FrameTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = socket.socketpair()

    def tearDown(self):
        for s in (self.a, self.b):
            try:
                s.close()
            except OSError:
                pass

    def _make_ws(self, sock):
        ws = object.__new__(pa.WS)
        ws.sock = sock
        return ws

    def test_small_payload_roundtrip(self):
        ws = self._make_ws(self.a)
        ws.send('hello')
        b2 = self._make_ws(self.b)
        self.assertEqual(b2.recv(), 'hello')

    def test_medium_payload_roundtrip(self):
        # 超过 125 字节走 126 扩展长度
        text = 'x' * 400
        ws = self._make_ws(self.a)
        ws.send(text)
        b2 = self._make_ws(self.b)
        self.assertEqual(b2.recv(), text)

    def test_json_message_roundtrip(self):
        msg = {'id': 7, 'method': 'Runtime.evaluate', 'params': {'expression': '1+1'}}
        ws = self._make_ws(self.a)
        ws.send(json.dumps(msg))
        b2 = self._make_ws(self.b)
        self.assertEqual(json.loads(b2.recv()), msg)


class EvaluateTests(unittest.TestCase):
    def test_evaluate_reads_return_by_value(self):
        class FakeWS:
            def call(self, msg_id, method, params=None):
                return {'id': msg_id, 'result': {'result': {'type': 'number', 'value': 2}}}

        value, err = pa.evaluate(FakeWS(), 1, '1+1')
        self.assertEqual(value, 2)
        self.assertIsNone(err)

    def test_evaluate_reports_exception(self):
        class FakeWS:
            def call(self, msg_id, method, params=None):
                return {'id': msg_id, 'result': {'exceptionDetails': {'text': 'boom'}}}

        value, err = pa.evaluate(FakeWS(), 1, 'throw 1')
        self.assertIsNone(value)
        self.assertIn('boom', err)


class BreakpointScriptTests(unittest.TestCase):
    def test_module_imports_and_has_main(self):
        import probe_breakpoint as pb

        self.assertTrue(callable(pb.main))
        self.assertTrue(callable(pb.recv_event))

    def test_recv_event_returns_none_on_timeout(self):
        import probe_breakpoint as pb

        a, b = socket.socketpair()
        try:
            ws = object.__new__(pa.WS)
            ws.sock = a
            # 对端不发数据，应当在超时后返回 None，而不是抛异常
            self.assertIsNone(pb.recv_event(ws, timeout=0.1))
        finally:
            a.close()
            b.close()


if __name__ == '__main__':
    unittest.main()
