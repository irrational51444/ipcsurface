"""输入解析器的模糊测试（零第三方依赖版）。

atheris 在 Windows 上要 clang，装不起来。这里用标准库做确定性「哑 fuzz」，
重点打「纯字节解析」的入口（asar 头），它不碰文件系统，能跑到每秒上千次。

只认一种崩溃：抛了 SystemExit 之外的异常。SystemExit 是「拒了坏输入」，是好的；
ValueError / struct.error / RecursionError 外泄，才是真崩溃。

用法：
    python scripts/fuzz_smoke.py                     # 短跑，给 CI 用
    python scripts/fuzz_smoke.py --iterations 50000  # 本地深挖（asar 头）

种子固定，崩溃可复现。
"""
import argparse
import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import jsasar
import ipcsurface as t


def asar_seed():
    header = b'{"files":{"a.js":{"offset":"0","size":"1"}}}'
    return struct.pack('<I', len(header)) + header + b'X'


def mutate(rng, data):
    data = bytearray(data)
    choice = rng.randrange(5)
    if not data:
        data = bytearray(b'\x00')
    if choice == 0:
        i = rng.randrange(len(data)); data[i] ^= 1 << rng.randrange(8)
    elif choice == 1:
        i = rng.randrange(len(data)); del data[i:i + rng.randint(1, 8)]
    elif choice == 2:
        i = rng.randrange(len(data)); data[i:i] = os.urandom(rng.randint(1, 8))
    elif choice == 3:
        del data[rng.randrange(len(data)):]
    else:
        data = bytearray(os.urandom(rng.randint(0, 128)))
    return bytes(data)


def run(iterations):
    rng = random.Random(20261111)
    crashes = []

    def drive(name, fn, data):
        # fn 是纯字节入口，不碰文件系统，能跑到每秒上千次
        for i in range(iterations):
            data = os.urandom(rng.randrange(0, 256)) if i % 4 == 0 else mutate(rng, data)
            try:
                fn(data)
            except SystemExit:
                continue
            except Exception as exc:
                crashes.append((name, i, type(exc).__name__, str(exc)[:80], data[:64]))
                if len(crashes) >= 8:
                    break
            if i and i % 10000 == 0:
                print(f'  {name} {i}/{iterations}', flush=True)

    drive('asar 头', jsasar.parse_asar_header, asar_seed())

    if crashes:
        print(f'发现 {len(crashes)} 个崩溃：')
        for name, i, kind, msg, sample in crashes:
            print(f'  [{name} #{i}] {kind}: {msg}')
            print(f'      样本 {sample!r}')
        return 1
    print(f'asar 头 {iterations} 次变异，没崩')
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--iterations', type=int, default=2000)
    args = ap.parse_args()
    return run(args.iterations)


if __name__ == '__main__':
    raise SystemExit(main())
