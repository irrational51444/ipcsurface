"""批量扫描与能力标签的用例。"""
import os
import struct
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, ROOT)

import batch_scan  # noqa: E402
import jslabels  # noqa: E402


def make_asar(files):
    entries = {}
    blobs = b''
    for name, content in files.items():
        entries[name] = {'size': len(content), 'offset': str(len(blobs))}
        blobs += content
    import json as _json
    jb = _json.dumps({'files': entries}).encode()
    inner = struct.pack('<I', len(jb)) + jb
    payload = struct.pack('<I', len(inner)) + inner
    return struct.pack('<I', 4) + struct.pack('<I', len(payload)) + payload + blobs


class RiskLabelTests(unittest.TestCase):
    def test_file_apis_are_fs(self):
        self.assertEqual(jslabels.risk_labels(['writeFileSync', 'readFileSync']), ['fs'])

    def test_process_apis_are_child_process(self):
        self.assertEqual(jslabels.risk_labels(['exec', 'spawn']), ['child_process'])

    def test_labels_are_deduplicated_and_ordered(self):
        # 顺序固定：fs 在 child_process 前，报告里不会随机跳
        got = jslabels.risk_labels(['exec', 'writeFileSync', 'fetch'])
        self.assertEqual(got, ['fs', 'child_process', 'network'])

    def test_unknown_api_has_no_label(self):
        self.assertEqual(jslabels.risk_labels(['not_a_danger_api']), [])

    def test_eval_and_shell_labels(self):
        self.assertEqual(jslabels.risk_labels(['eval']), ['eval'])
        self.assertEqual(jslabels.risk_labels(['openExternal']), ['shell'])


class BatchScanTests(unittest.TestCase):
    def test_collect_accepts_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            asar = os.path.join(folder, 'x.asar')
            with open(asar, 'wb') as fh:
                fh.write(make_asar({'a.js': b'x'}))
            got = batch_scan.collect([folder])
            self.assertEqual([os.path.basename(p) for p in got], ['x.asar'])

    def test_collect_dedupes_same_file(self):
        with tempfile.TemporaryDirectory() as folder:
            asar = os.path.join(folder, 'x.asar')
            with open(asar, 'wb') as fh:
                fh.write(make_asar({'a.js': b'x'}))
            got = batch_scan.collect([asar, folder])
            self.assertEqual(len(got), 1, '同一个包给了两次（直接给 + 目录）应当只算一次')

    def test_scan_one_reports_labels(self):
        with tempfile.TemporaryDirectory() as folder:
            asar = os.path.join(folder, 'app.asar')
            body = (b"const {ipcMain} = require('electron');\n"
                    b"const fs = require('fs');\n"
                    b"ipcMain.handle('save', (e, p) => fs.writeFileSync(p, 'x'));\n")
            with open(asar, 'wb') as fh:
                fh.write(make_asar({'main.js': body}))
            row = batch_scan.scan_one(asar)
            self.assertEqual(row['channels'], 1)
            self.assertEqual(row['danger_channels'], 1)
            self.assertEqual(row['risk_labels'], {'fs': 1})

    def test_label_prefers_file_stem(self):
        self.assertEqual(batch_scan.label_of('/x/y/static-asar.asar'), 'static-asar')
        self.assertIn('/app', batch_scan.label_of('/x/DeepSeek Harness/resources/app.asar'))


if __name__ == '__main__':
    unittest.main()
