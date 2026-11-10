"""asar 读取层：只负责把包拆成「文件表 + 按需切片」。

从 ipcsurface.py 里切出来的第一刀。理由很实在：主模块已经五千多行，
里面的 asar 解析、能力面扫描、语法树、报告渲染互相缠在一起，改一处要读全部。
这一层只依赖标准库的 struct/json/os/mmap，把它单拎出来之后，
上层（扫描、分析、报告）以后可以各走各的。

对外仍然只有两个名字：AsarFiles 和 read_asar。ipcsurface 会重新导出它们，
所以老的调用方（包括测试和其它脚本）一个字都不用改。
"""
import json
import mmap
import os
import struct


class AsarFiles:
    """asar 里的文件，谁要谁去切，不整包搬进内存。

    四百多兆的包里，有两百多兆是图片字体这类我们连碰都不碰的东西。
    以前一口气全读进来，峰值就是载荷的一倍多；现在只记偏移，
    按需从 mmap 里切片，切出来的那份用完就丢。
    """

    def __init__(self, path, spans):
        self.path = path
        self.spans = spans
        self._file = None
        self._mm = None

    def keys(self):
        return self.spans.keys()

    def items(self):
        # 兼容老接口：以前文件表就是个 dict，现在按需切。
        for name in self.spans:
            yield name, self.read(name)

    def __getitem__(self, name):
        data = self.read(name)
        if data is None:
            raise KeyError(name)
        return data

    def __iter__(self):
        return iter(self.spans)

    def __contains__(self, name):
        return name in self.spans

    def __len__(self):
        return len(self.spans)

    def open(self):
        if self._file is None:
            self._file = open(self.path, 'rb')
            self._mm = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        return self._mm

    def read(self, name):
        """按需切一份出来；没有就是 None。"""
        span = self.spans.get(name)
        if span is None:
            return None
        offset, size = span
        mm = self.open()
        return mm[offset:offset + size]

    def total_bytes(self):
        """整包大小（所有文件加起来，不含头）。报告里的「多少 MB」用它。"""
        return sum(size for _offset, size in self.spans.values())

    def size_of(self, name):
        span = self.spans.get(name)
        return span[1] if span else 0

    def close(self):
        if self._mm is not None:
            try:
                self._mm.close()
            except BufferError:
                pass
            self._mm = None
        if self._file is not None:
            self._file.close()
            self._file = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def read_asar(path):
    """解一个 asar，返回 (文件树, 文件表)。

    asar 的头是个 pickle：8 字节前缀，其中后 4 字节是头部长度；
    头部本身又是 4 字节长度 + JSON。

    文件表不装内容，只装位置。要哪份切哪份。
    """
    with open(path, 'rb') as fh:
        head = fh.read(8)
        if len(head) < 8:
            raise SystemExit('这不是 asar：文件太短')
        header_size = struct.unpack('<I', head[4:8])[0]
        payload = fh.read(header_size)
        if len(payload) < header_size:
            raise SystemExit('这不是 asar：头部被截断')
        # 头部是层叠的 pickle：几层长度前缀，后面才是 JSON。
        # 不数层数，直接找第一个 { 让它自己解，省得跟着版本变。
        text = payload.decode('utf-8', 'replace')
        start = text.find('{')
        if start < 0:
            raise SystemExit('这不是 asar：头部找不到 JSON')
        try:
            header, _ = json.JSONDecoder().raw_decode(text[start:])
        except json.JSONDecodeError:
            raise SystemExit('这不是 asar：头部不是合法 JSON')
        base = 8 + header_size

    spans = {}

    def walk(node, prefix):
        for name, child in (node.get('files') or {}).items():
            rel = f'{prefix}{name}'
            if 'files' in child:
                walk(child, rel + '/')
            else:
                offset = int(child.get('offset', 0))
                size = int(child.get('size', 0))
                spans[rel] = (base + offset, size)

    walk(header, '')
    return header, AsarFiles(path, spans)


def looks_like_asar(path):
    """头 8 字节对不对得上——别把 zip 当 asar 解。"""
    try:
        with open(path, 'rb') as fh:
            head = fh.read(8)
    except OSError:
        return False
    if len(head) < 8:
        return False
    size = struct.unpack('<I', head[4:8])[0]
    return 0 < size < os.path.getsize(path)
