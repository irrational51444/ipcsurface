"""把运行时探针吐的 JSONL 变成 ipcsurface 能吃的 probe JSON。

探针（scripts/probe_preload.js）每注册一条通道写一行：
  {"kind":"handle","channel":"app:x","type":"string","site":"…/main.js:12:3 | …"}
这里只做转换，不做判断：
- handlers / listeners 按 kind 分开（handle≠on，语义不同）
- sites 只在行号看得见时才写；看不见就不写，别造一个假位置
  —— 报告里「位置缺失」读作 unknown，这是有意的语义。

用法：python scripts/probe_to_json.py ipc-probe.jsonl > probe.json
"""
import json
import re
import sys

HANDLE_KINDS = {'handle', 'handleOnce'}
LINE_RE = re.compile(r'([\w@./\\-]+\.\w+):(\d+):(\d+)')


def convert(lines):
    handlers, listeners, sites, errors = [], [], {}, []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except ValueError:
            continue
        kind = row.get('kind')
        if kind == 'probe-error':
            errors.append(row.get('error'))
            continue
        channel = row.get('channel')
        if not channel:
            continue
        bucket = handlers if kind in HANDLE_KINDS else listeners
        if channel not in bucket:
            bucket.append(channel)
        match = LINE_RE.search(row.get('site') or '')
        if match:
            name, line = match.group(1), match.group(2)
            sites.setdefault(channel, f'{name}:{line}')
    out = {
        'handlers': handlers,
        'listeners': listeners,
        'sites': sites,
    }
    if errors:
        out['error'] = '; '.join(errors)
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    with open(sys.argv[1], encoding='utf-8', errors='replace') as fh:
        probe = convert(fh)
    json.dump(probe, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write('\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
