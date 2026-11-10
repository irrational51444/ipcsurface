"""探针转换器的用例：位置看得到才写，看不到不许编。"""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'scripts', 'probe_to_json.py')

SAMPLE = '\n'.join([
    json.dumps({'kind': 'handle', 'channel': 'app:a',
                'type': 'string', 'site': 'C:/app/main.js:12:4 | x'}),
    json.dumps({'kind': 'on', 'channel': 'app:b', 'type': 'string', 'site': ''}),
    json.dumps({'kind': 'handle', 'channel': 'app:a',
                'type': 'string', 'site': 'C:/app/main.js:12:4 | x'}),
    json.dumps({'kind': 'probe-error', 'error': 'boom'}),
]) + '\n'


class ProbeConvertTests(unittest.TestCase):
    def run_convert(self, text):
        fd, path = tempfile.mkstemp(suffix='.jsonl')
        os.close(fd)
        try:
            with io.open(path, 'w', encoding='utf-8') as fh:
                fh.write(text)
            proc = subprocess.run([sys.executable, SCRIPT, path],
                                  capture_output=True, text=True,
                                  encoding='utf-8', errors='replace')
            self.assertEqual(proc.returncode, 0, proc.stderr)
            return json.loads(proc.stdout)
        finally:
            os.unlink(path)

    def test_handlers_and_listeners_split(self):
        probe = self.run_convert(SAMPLE)
        self.assertEqual(probe['handlers'], ['app:a'])
        self.assertEqual(probe['listeners'], ['app:b'])

    def test_duplicate_channel_counted_once(self):
        probe = self.run_convert(SAMPLE)
        self.assertEqual(len(probe['handlers']), 1)

    def test_site_only_when_line_is_visible(self):
        probe = self.run_convert(SAMPLE)
        self.assertIn('app:a', probe['sites'])
        self.assertNotIn('app:b', probe['sites'], '没位置就别造一个')

    def test_probe_error_is_reported(self):
        probe = self.run_convert(SAMPLE)
        self.assertIn('boom', probe.get('error', ''))


if __name__ == '__main__':
    unittest.main()
