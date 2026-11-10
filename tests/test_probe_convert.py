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


class RealRunTests(unittest.TestCase):
    """真跑留下的样本：electron v45 起的一个最小应用，探针抓到的四条。

    这个文件是从真机上跑出来的（不是编的），所以它盯的不只是格式，
    还盯住「运行时能看见静态看不见的那两条」这件事。
    """

    SAMPLE = os.path.join(ROOT, 'tests', 'golden', 'probe_sample.jsonl')

    def test_real_run_four_channels(self):
        with io.open(self.SAMPLE, encoding='utf-8') as fh:
            probe = json.loads(subprocess.run(
                [sys.executable, SCRIPT, self.SAMPLE],
                capture_output=True, text=True, encoding='utf-8', errors='replace').stdout)
        self.assertEqual(sorted(probe['handlers']), ['probe-dynamic', 'probe:literal'])
        self.assertEqual(sorted(probe['listeners']), ['probe:concat', 'probe:from-object'])
        self.assertEqual(len(probe['sites']), 4, '四条都该带位置')

    def test_static_sees_fewer_than_runtime(self):
        """静态只认得字面量那条；另外三条要运行时才知道。"""
        import jsparse
        src = os.path.join(ROOT, 'build', 'electron-probe', 'app', 'main.js')
        if not os.path.exists(src):
            self.skipTest('真跑用的最小 app 不在（build 目录不入库）')
        with io.open(src, encoding='utf-8') as fh:
            tokens = jsparse.tokenize(fh.read())
        named = [r['channel'] for r in jsparse.ipc_registrations(tokens, {}) if r['channel']]
        self.assertEqual(named, ['probe:literal'])


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
