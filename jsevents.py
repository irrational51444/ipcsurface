"""jsevents —— 实时事件层：把扫描过程变成一条可录、可回放的事件流。

设计来自《ipcsurface 实时报告系统设计》，这里只落 P1：EventBus + JSONL。

四条硬规矩（少一条这套就变成第二套真相）：
1. **内核不认识呈现层**：扫描器只调 `emit()`，不知道有没有人在看。
2. **不加 --events-out 时零开销**：`bus` 传 None，`emit()` 第一行就返回。
3. **有界队列 + 分级丢弃**：队列满了只丢 `progress`/`stats`，
   `discovery`/`evidence`/`warning`/`unresolved`/`lifecycle` 一条都不许丢。
4. **evidence 只追加**：一条通道从借来档升到直连档，不是改写旧事件，是再发一条。
   实时报告展示的是「证据怎么演化」，不是「结论怎么被覆盖」。
"""
import json
import os
import time
from collections import deque

# 事件格式的版本号。和报告 schema 分开走：事件流改了不一定要动报告 schema。
SCHEMA = 'ipcsurface/event/1'

KINDS = ('lifecycle', 'progress', 'discovery', 'evidence', 'warning',
         'unresolved', 'stats')
# 可以丢的事件：高频、可采样、丢了不影响对账
DROPPABLE = frozenset(('progress', 'stats'))
PHASES = ('coarse', 'tree', 'precise', 'probe', 'report')

# 队列上限、批量写入阈值、flush 间隔，和设计文档保持一致
DEFAULT_MAX_QUEUE = 10000
FLUSH_EVERY = 64
FLUSH_INTERVAL = 0.1


def now_iso():
    """UTC 时间戳，毫秒精度，和报告里的时间格式一致。"""
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime()) + \
        '.%03dZ' % (int(time.time() * 1000) % 1000)


class EventBus:
    """一条事件流。写 JSONL，append-only，可按 seq 对账。

    用法：
        bus = EventBus(path, scan_id=merkle)
        bus.emit('lifecycle', {'stage': 'start', 'input': name, 'size': total})
        ...
        bus.emit('lifecycle', {'stage': 'done', ...})
        bus.close()
    """

    def __init__(self, path=None, scan_id='', max_queue=DEFAULT_MAX_QUEUE,
                 flush_every=FLUSH_EVERY, flush_interval=FLUSH_INTERVAL,
                 clock=now_iso):
        self.path = path
        self.scan_id = scan_id
        self.max_queue = max_queue
        self.flush_every = flush_every
        self.flush_interval = flush_interval
        self._clock = clock
        self._queue = deque()
        self._seq = 0
        self._sent = 0
        self._dropped = 0
        self._bytes = 0
        self._last_flush = time.monotonic()
        self._fh = None
        if path:
            folder = os.path.dirname(os.path.abspath(path))
            if folder and not os.path.isdir(folder):
                os.makedirs(folder, exist_ok=True)
            self._fh = open(path, 'w', encoding='utf-8', newline='\n')

    # ---------------------------------------------------------------- 发射
    def emit(self, kind, payload=None, phase='coarse'):
        """发一条事件。返回 True 表示接受了，False 表示被丢弃。"""
        if kind not in KINDS:
            raise ValueError('不认识的 kind: %r' % (kind,))
        if phase not in PHASES:
            raise ValueError('不认识的 phase: %r' % (phase,))
        if len(self._queue) >= self.max_queue:
            if kind in DROPPABLE:
                self._dropped += 1
                return False
            # 不可丢的事件碰上满队列：把最老的可丢事件挤掉腾位置
            for i, item in enumerate(self._queue):
                if item['kind'] in DROPPABLE:
                    del self._queue[i]
                    self._dropped += 1
                    break
            else:
                self._dropped += 1
                return False

        self._seq += 1
        event = {
            'schema': SCHEMA,
            'seq': self._seq,
            'ts': self._clock(),
            'scan_id': self.scan_id,
            'phase': phase,
            'kind': kind,
            'payload': payload if payload is not None else {},
        }
        self._queue.append(event)
        if len(self._queue) >= self.flush_every:
            self.flush()
        elif time.monotonic() - self._last_flush >= self.flush_interval:
            self.flush()
        return True

    # ------------------------------------------------------------------ 写
    def flush(self):
        """把队列里的都写出去。返回写了多少条。"""
        if not self._queue:
            self._last_flush = time.monotonic()
            return 0
        count = 0
        chunks = []
        while self._queue:
            event = self._queue.popleft()
            try:
                chunks.append(json.dumps(event, ensure_ascii=False,
                                         separators=(',', ':')))
            except (TypeError, ValueError):
                # 序列化不了的事件不能把整条流带崩：记一条 dropped 就算了
                self._dropped += 1
                continue
            count += 1
        if chunks and self._fh is not None:
            blob = '\n'.join(chunks) + '\n'
            self._fh.write(blob)
            self._fh.flush()
            self._bytes += len(blob.encode('utf-8'))
        self._sent += count
        self._last_flush = time.monotonic()
        return count

    def close(self):
        """收尾：把剩下的写完，关文件。返回统计。"""
        self.flush()
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None
        return self.stats()

    # ---------------------------------------------------------------- 查询
    def stats(self):
        return {
            'sent': self._sent,
            'dropped': self._dropped,
            'queued': len(self._queue),
            'bytes': self._bytes,
            'last_seq': self._seq,
        }

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def last_summary(path):
    """读一条 JSONL，返回最后一条事件的 payload（对账用）。

    读不到或空文件返回 None —— 调用方要自己判断「没有事件」和「统计为 0」的区别。
    """
    if not path or not os.path.exists(path):
        return None
    last = None
    with open(path, encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                last = json.loads(line)
            except ValueError:
                continue
    return last


def report_summary(report):
    """从报告 JSON 里算出和 lifecycle.done 同口径的统计。

    报告里 channels 是列表、channel_sink_tiers 是嵌套字典，不是现成的数；
    这里用和 analyse_asar 完全一样的口径重算一遍，才能和事件流逐项比。
    """
    tiers = report.get('channel_sink_tiers') or {}
    by_tier = {}
    for ch_tiers in tiers.values():
        for tier in (ch_tiers or {}).values():
            by_tier[tier] = by_tier.get(tier, 0) + 1
    sink_src = report.get('channel_sinks_ast') or report.get('channel_sinks') or {}
    return {
        'channels': len(report.get('channels') or []),
        'sinks': sum(len(v) for v in sink_src.values() if v),
        'by_tier': by_tier,
        'unresolved': len(report.get('dynamic') or []),
    }


def diff_summary(events_path, report):
    """对账：事件流末条统计 vs 报告顶层统计。返回差异列表，空表示一致。

    设计守则 4：实时视图与最终报告的数字必须可对账。对不上就是设计坏了，
    不是「数据有点小误差」。
    """
    last = last_summary(events_path)
    if not last:
        return ['事件流是空的，没法对账']
    payload = last.get('payload') or {}
    if last.get('kind') != 'lifecycle' or payload.get('stage') != 'done':
        return ['事件流最后一条不是 lifecycle.done（实际 %r）' % (last.get('kind'),)]
    actual = report_summary(report)
    problems = []
    for key in ('channels', 'sinks', 'by_tier', 'unresolved'):
        if payload.get(key) != actual.get(key):
            problems.append('%s 对不上：事件 %r vs 报告 %r'
                            % (key, payload.get(key), actual.get(key)))
    return problems
