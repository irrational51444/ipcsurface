"""OSS-Fuzz / atheris 的 fuzz target（在 Linux CI 上跑，本机 Windows 没 clang 不用跑）。

三个入口：
- parse_asar_header  —— asar 头（纯字节）
- parse_pe_bytes     —— PE 导入表（纯字节）
- load_record        —— Evidence JSON（走文件，atheris 给的字节写临时文件）

atheris 是 libFuzzer 的 Python 绑定，靠 OSS-Fuzz 的 harness 起。这里只写 target，
真正起 fuzz 的是 OSS-Fuzz 的 build.sh（见同目录）。
"""
import atheris
import os
import sys

# 用脚本目录的父目录（项目根）进 sys.path，别用相对 '..'——那依赖 cwd。
# CI 从仓库根跑 `python fuzz/atheris_fuzz.py` 时，'..' 指向仓库根上一级，jsasar 找不到。
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ipcsurface as t  # noqa: E402
import jsasar  # noqa: E402


def _tmp(data):
    import os
    import tempfile
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
        t.load_record(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def TestOneInput(data):
    # 三个 target 都喂一遍同一份字节，谁崩都算。
    for fn in (jsasar.parse_asar_header, t.parse_pe_bytes):
        try:
            fn(data)
        except SystemExit:
            pass
    try:
        _tmp(data)
    except SystemExit:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
