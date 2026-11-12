"""分支覆盖率门禁：用例数只能说明「写了多少」，覆盖才能说明「测到哪」。

这是路线图 P0-2 的落地。只许涨不许跌：阈值从实测值起步，本文件提交时是 68%；
后来把 native_imports 纳入统计、补了 jslabels / native_imports 的用例。CI 的
Python 3.12 分支统计比本机 3.13 略严，实测 67%，所以锁 67% 作门槛——这是
「按新环境重新实测」，不是倒退；想提回 68%，补覆盖就行。

用法：
    python scripts/coverage_check.py            # 默认阈值
    COVERAGE_THRESHOLD=70 python scripts/coverage_check.py

依赖 coverage.py（开发期依赖，不是产品依赖；产品仍然零依赖）。
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# precise_engine 是 opt-in 精查层，CI 默认不装 tree-sitter 时它的用例全 skip、
# 覆盖率不可控，所以不进 PRODUCT（它的覆盖由 tests/test_precise.py 在本机锁）。
PRODUCT = ('ipcsurface.py,jsasar.py,jslabels.py,jsparse.py,jssem.py,jsast.py,'
           'jsreport.py,native_imports.py,jsevents.py')
# CI 的 Python 3.12 分支统计比本机 3.13 略严（实测 67% vs 68%），取更严的 67%
# 锁门槛，别让版本差异造成假红；本机 3.13 跑是 68%。
THRESHOLD = float(os.environ.get('COVERAGE_THRESHOLD', '67'))


def main():
    env = dict(os.environ)
    env.setdefault('PYTHONUTF8', '1')
    env.setdefault('PYTHONIOENCODING', 'utf-8')

    run = subprocess.run([sys.executable, '-m', 'coverage', 'run', '--branch',
                          '-m', 'unittest', 'discover', '-s', 'tests'],
                         cwd=ROOT, capture_output=True, text=True,
                         encoding='utf-8', errors='replace')
    if run.returncode != 0:
        print('用例没全过，先修用例再谈覆盖：')
        print((run.stdout + run.stderr)[-2000:])
        return 2

    rep = subprocess.run([sys.executable, '-m', 'coverage', 'report',
                          '--include', PRODUCT],
                         cwd=ROOT, capture_output=True, text=True,
                         encoding='utf-8', errors='replace')
    text = rep.stdout
    print(text)

    m = re.search(r'TOTAL\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)%', text)
    if not m:
        print('没读到 TOTAL 行，coverage 输出格式变了')
        return 2
    cover = int(m.group(1))
    ok = cover >= THRESHOLD
    print(f'分支覆盖率 {cover}% ，门槛 {THRESHOLD}% ——', '过' if ok else '红')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
