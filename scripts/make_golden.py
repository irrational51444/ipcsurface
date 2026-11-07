"""按纪律重新生成金标准快照。必须给 --reason，必须写清为什么。

    python scripts/make_golden.py --reason "增加 XXX 字段，下游需要适配"

理由会追加到 tests/golden/CHANGELOG.golden.md，和快照一起进 git。
"""
import argparse
import datetime
import json
import os
import struct
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import ipcsurface as t  # noqa: E402

GOLDEN = os.path.join(ROOT, 'tests', 'golden', 'asar_report.json')
LOGFILE = os.path.join(ROOT, 'tests', 'golden', 'CHANGELOG.golden.md')


def make_asar(files):
    entries = {}
    blobs = b''
    for name, content in files.items():
        entries[name] = {'size': len(content), 'offset': str(len(blobs))}
        blobs += content
    jb = json.dumps({'files': entries}).encode()
    inner = struct.pack('<I', len(jb)) + jb
    payload = struct.pack('<I', len(inner)) + inner
    return struct.pack('<I', 4) + struct.pack('<I', len(payload)) + payload + blobs


def build_report():
    blob = make_asar({'src/app.js': b"ipcMain.handle('a:b', f)"})
    fd, path = tempfile.mkstemp(suffix='.asar')
    with os.fdopen(fd, 'wb') as fh:
        fh.write(blob)
    try:
        facts, count, total = t.analyse_asar(path)
        names = {n for n, _ in facts['handlers']} | {n for n, _ in facts['invokes']}
        evidence = t.channel_sources(facts)
        report = t.build_asar_report(path, facts, count, total, names, evidence,
                                    t.runtime_crosscheck(None, names), None, None)
    finally:
        os.unlink(path)
    report['subject'] = '<fixture>'
    report['version'] = '<version>'
    return report


def main():
    parser = argparse.ArgumentParser(description='重新生成金标准快照')
    parser.add_argument('--reason', required=True,
                        help='为什么这次必须变；会写进 CHANGELOG.golden.md')
    args = parser.parse_args()

    reason = args.reason.strip()
    if len(reason) < 10:
        raise SystemExit('理由太短。写清「哪个字段、为什么必须变、下游要不要适配」，'
                         '不然这份快照迟早变成「红了就覆盖」。')

    before = None
    if os.path.exists(GOLDEN):
        with open(GOLDEN, encoding='utf-8') as fh:
            before = json.load(fh)

    report = build_report()
    changed = []
    if before:
        changed = sorted(k for k in set(before) | set(report)
                         if before.get(k) != report.get(k))
    if before and not changed:
        print('快照没有变化，不用重写。', file=sys.stderr)
        print('（这次的 reason 没有写进 CHANGELOG.golden.md：内容没变。'
              '如果你本来以为会变，那说明改的不是这里。）', file=sys.stderr)
        return 0

    with open(GOLDEN, 'w', encoding='utf-8', newline='\n') as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    stamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    entry = [f'\n## {stamp}', '', f'- 变了的字段：{", ".join(changed) or "（首次生成）"}',
             f'- 理由：{reason}', '']
    if not os.path.exists(LOGFILE):
        with open(LOGFILE, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write('# 金标准快照变更记录\n\n'
                     '格式固定，由 scripts/make_golden.py 写入：\n\n'
                     '    ## YYYY-MM-DD HH:MM\n'
                     '    - 变了的字段：a, b\n'
                     '    - 理由：...\n\n'
                     '最新的追加在文件末尾。人工不要改格式，脚本解析靠它。\n')
    with open(LOGFILE, 'a', encoding='utf-8', newline='\n') as fh:
        fh.write('\n'.join(entry))
    print(f'快照已更新；变了的字段：{", ".join(changed) or "（首次生成）"}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
