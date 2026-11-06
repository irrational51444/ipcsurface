"""喂一堆畸形输入，看它是报错还是装作没事。"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ipcsurface as t

CASES = {}


def case(name):
    def wrap(fn):
        CASES[name] = fn
        return fn
    return wrap


def write(data, binary=False):
    mode = 'wb' if binary else 'w'
    kwargs = {} if binary else {'encoding': 'utf-8'}
    fh = tempfile.NamedTemporaryFile(mode=mode, suffix='.json', delete=False, **kwargs)
    fh.write(data)
    fh.close()
    return fh.name


@case('空文件')
def _():
    return write('')


@case('截断的 JSON')
def _():
    return write('{"handlers": ["a:b", "c:d"')


@case('不是 JSON 的文本')
def _():
    return write('这就是一段话，不是 JSON')


@case('合法 JSON 但类型不对：数组')
def _():
    return write('[1, 2, 3]')


@case('合法 JSON 但类型不对：字符串')
def _():
    return write('"hello"')


@case('超深嵌套')
def _():
    return write('[' * 20000 + ']' * 20000)


@case('非法 UTF-8 字节')
def _():
    return write(b'{"handlers": ["\xff\xfe"]}', binary=True)


@case('JSON 里 handlers 不是列表')
def _():
    return write(json.dumps({'handlers': 'a:b'}))


def main():
    for name, make in CASES.items():
        path = make()
        try:
            for label, fn in (('load_probe', t.load_probe),
                              ('load_poke', t.load_poke),
                              ('load_baseline', t.load_baseline)):
                try:
                    result = fn(path)
                    kind = type(result).__name__
                    preview = str(result)[:60].replace('\n', ' ')
                    print(f'  [没问题？ ] {name:26} {label:14} 返回 {kind}: {preview}')
                except SystemExit as exc:
                    print(f'  [拒绝    ] {name:26} {label:14} {str(exc)[:50]}')
                except Exception as exc:                     # noqa: BLE001
                    print(f'  [崩了    ] {name:26} {label:14} {type(exc).__name__}: {exc}')
        finally:
            os.unlink(path)


if __name__ == '__main__':
    main()
