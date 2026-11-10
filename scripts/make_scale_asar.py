"""造一个「规模对得上」的 asar，让外部的人也能把性能数字跑出来。

为什么要有这个：README 里的规模断言一直跑在本机的 441 MB 应用上，
别人手上没有那台机器，数字就没法复现——那只是我的数，不是公布的数。
这里用固定种子生成同样量级的包（文件数、字节数都写在参数里），
同样的参数、同样的机器，出来的数字应当差不多；生成过程不联网、不随机。
"""
import argparse
import hashlib
import json
import os
import struct

HEADER_MARKER = b'\x04\x00\x00\x00'


def build_asar(entries, out_path):
    """entries: [(name, bytes)]，按 asar 的格式写成单文件。"""
    files = {}
    offset = 0
    blob_parts = []
    ordered = sorted(entries, key=lambda item: item[0])
    base = 0
    for name, data in ordered:
        node = files
        parts = name.split('/')
        for part in parts[:-1]:
            node = node.setdefault(part, {}).setdefault('files', {})
        node[parts[-1]] = {'size': len(data), 'offset': str(offset)}
        offset += len(data)
        blob_parts.append(data)
    header = json.dumps({'files': files}, separators=(',', ':')).encode('utf-8')
    pad = (4 - len(header) % 4) % 4
    header += b' ' * pad
    # 布局按读法来：8 字节前缀（后 4 字节是头部长度）+ 头部 + 内容。
    # 早先多写了两层长度前缀，自己写出来的包自己都读不了——生成器也得被验证。
    with open(out_path, 'wb') as fh:
        fh.write(struct.pack('<I', 4))
        fh.write(struct.pack('<I', len(header)))
        fh.write(header)
        for part in blob_parts:
            fh.write(part)
    del base
    return out_path


JS_SKELETON = """const {ipcMain} = require('electron');
const fs = require('fs');
function h%(n)d(event, payload) {
  try { if (payload && payload.path) fs.readFileSync(payload.path); } catch (err) {}
  return payload && payload.value;
}
ipcMain.handle('scale:%(n)d', h%(n)d);
ipcMain.on('scale:note:%(n)d', () => {});
// 填充：让单文件大小接近真包里的打包产物
%(filler)s
"""


def make_entries(file_count, target_bytes, seed='ipcsurface'):
    entries = []
    per_file = max(2048, target_bytes // max(1, file_count))
    filler_line = '// ' + 'x' * 200 + '\n'
    for i in range(file_count):
        h = hashlib.sha256(('%s:%d' % (seed, i)).encode()).hexdigest()
        skeleton = JS_SKELETON % {
            'n': i,
            'filler': filler_line * max(1, (per_file // len(filler_line))),
        }
        body = ('// %s\n' % h) + skeleton
        entries.append(('pkg/mod%03d/file%05d.js' % (i % 64, i), body.encode('utf-8')))
    entries.append(('package.json', b'{"name":"scale-fixture","main":"pkg/mod000/file00000.js"}'))
    return entries


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('out')
    ap.add_argument('--files', type=int, default=22102)
    ap.add_argument('--mb', type=int, default=441)
    args = ap.parse_args()
    entries = make_entries(args.files, args.mb * 1024 * 1024)
    build_asar(entries, args.out)
    size = os.path.getsize(args.out)
    print('写好 %s：%d 个文件，%.1f MB' % (args.out, len(entries), size / 1024.0 / 1024.0))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
