"""性能门禁：固定种子造一个规模包，扫一遍，断言吞吐不低于下限。

路线图 P1-6 的落地。以前「16.5s / 27 MB/s」只挂在作者本机，性能倒退没人发现。
这里用 scripts/make_scale_asar.py 的固定种子造包（不联网、不随机），任何机器都能
复现同一个包、跑出同一个量级的吞吐；掉到下限以下 CI 就红。

用法：
    python scripts/perf_check.py                     # 默认 40MB 夹具、下限 15 MB/s
    PERF_MB=120 PERF_FLOOR=20 python scripts/perf_check.py

平台差异：CI 的 ubuntu 和作者本机 Windows 吞吐不同，所以下限设得保守（15 MB/s），
只挡「明显倒退」，不挡平台噪声。真要收紧，测完本平台实测值再调 PERF_FLOOR。
"""
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import ipcsurface as t  # noqa: E402

PERF_MB = int(os.environ.get('PERF_MB', '40'))
PERF_FLOOR = float(os.environ.get('PERF_FLOOR', '15'))   # MB/s，吞吐下限


def main():
    tmp = tempfile.mkdtemp()
    fixture = os.path.join(tmp, 'perf.asar')
    try:
        subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'make_scale_asar.py'),
                        fixture, '--files', '2000', '--mb', str(PERF_MB)],
                       cwd=ROOT, check=True, capture_output=True, text=True)
        mb = os.path.getsize(fixture) / 1024.0 / 1024.0
        started = time.time()
        t.analyse_asar(fixture)
        elapsed = time.time() - started
        throughput = mb / elapsed if elapsed else 0
        ok = throughput >= PERF_FLOOR
        print(f'性能门禁：{mb:.0f} MB 扫了 {elapsed:.2f}s，吞吐 {throughput:.1f} MB/s，'
              f'下限 {PERF_FLOOR:.0f} MB/s ——', '过' if ok else '红')
        return 0 if ok else 1
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    raise SystemExit(main())
