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
        self._listeners = []
        self._fh = None
        if path:
            folder = os.path.dirname(os.path.abspath(path))
            if folder and not os.path.isdir(folder):
                os.makedirs(folder, exist_ok=True)
            self._fh = open(path, 'w', encoding='utf-8', newline='\n')

    def add_listener(self, fn):
        """挂一个订阅者（终端渲染器之类）。返回 fn，方便链式写。

        订阅者必须是 O(1) 的：它在扫描线程上同步调用，慢了就是拖慢扫描。
        需要重绘的东西自己攒着、按时间节流。
        """
        self._listeners.append(fn)
        return fn

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
        # 订阅者同步调用：它们必须 O(1)，快的几微秒，慢的自己节流。
        for fn in self._listeners:
            try:
                fn(event)
            except Exception:  # noqa: BLE001 —— 渲染器炸了不能把扫描带崩
                pass
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


# ---------------------------------------------------------------- 终端渲染
# 符号和颜色是全局约定，Web 端以后也用这一套。
# 最要紧的一条：**借来档必须是灰的**。ambiguous（53%）和 ast_only（25%）
# 如果被染成黄/红，就等于在视觉上把「可能错」伪装成「很可能对」。
TIER_GLYPH = {
    'direct': ('þ', '32'),          # 绿
    'name_confirmed': ('þ', '32'),  # 绿
    'chain': ('◐', '33'),           # 黄
    'ambiguous': ('¨', '90'),       # 灰（借来档）
    'ast_only': ('¨', '90'),        # 灰（借来档）
}
GLYPH_UNKNOWN = ('·', '90')
# 借来档白名单：这两个档位在任何视图里都不许用红/黄
BORROWED_TIERS = frozenset(('ambiguous', 'ast_only'))


def enable_ansi():
    """Windows 上打开 VT 转义。失败就静默：大不了没颜色，不能把扫描搞崩。"""
    if os.name != 'nt':
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:  # noqa: BLE001 —— 拿不到控制台就算了
        return False


def colorize(text, code, use_color=True):
    if not use_color or not code:
        return text
    return '\033[%sm%s\033[0m' % (code, text)


def tier_glyph(tier):
    """档位 → (符号, ANSI 码)。不认识的档位给灰点，不给绿色。"""
    return TIER_GLYPH.get(tier or '', GLYPH_UNKNOWN)


class TerminalRenderer:
    """把事件流画到终端：80 列、ANSI、借来档必须灰。

    订阅者是同步调用的，所以 on_event 只做 O(1) 的记账，重绘按时间节流
    （默认 0.5 秒一次）。这样扫描不会被渲染拖慢。
    """

    def __init__(self, stream=None, width=80, interval=0.5, use_color=True,
                 max_rows=12, clock=None):
        self.stream = stream
        self.width = max(40, width)
        self.interval = interval
        self.use_color = use_color
        self.max_rows = max_rows
        self._clock = clock or time.monotonic
        self._last_paint = 0.0
        self._input = ''
        self._size = None
        self._phase = 'coarse'
        self._files_done = 0
        self._files_total = 0
        self._elapsed_ms = 0
        self._channels = []
        self._seen_channels = set()
        self._stats = {}
        self._done = None

    # ------------------------------------------------------------ 事件入口
    def on_event(self, event):
        kind = event.get('kind')
        payload = event.get('payload') or {}
        if kind == 'lifecycle':
            stage = payload.get('stage')
            if stage == 'start':
                self._input = payload.get('input') or ''
                self._size = payload.get('size')
            elif stage == 'done':
                self._done = payload
                self._phase = 'report'
        elif kind == 'progress':
            self._files_done = payload.get('files_done') or 0
            self._files_total = payload.get('files_total') or 0
            self._elapsed_ms = payload.get('elapsed_ms') or 0
        elif kind == 'discovery':
            name = payload.get('name')
            if name and name not in self._seen_channels:
                self._seen_channels.add(name)
                self._channels.append((name, payload.get('tier')))
        elif kind == 'stats':
            self._stats = payload
        self._phase = event.get('phase') or self._phase

        now = self._clock()
        if now - self._last_paint >= self.interval:
            self.paint()
            self._last_paint = now

    # ---------------------------------------------------------------- 绘制
    def _line(self, text):
        if len(text) > self.width:
            text = text[:self.width - 1] + '…'
        return text

    def _rate(self):
        if not self._elapsed_ms or not self._size:
            return ''
        seconds = self._elapsed_ms / 1000.0
        if seconds <= 0:
            return ''
        return '%.1f MB/s' % (self._size / 1048576.0 / seconds)

    def render(self):
        """返回要打印的整段文本（测试直接拿这个比对）。"""
        out = []
        size = ''
        if self._size:
            size = '  %.1f MB' % (self._size / 1048576.0)
        out.append(self._line('ipcsurface live | %s%s' % (self._input or '?', size)))
        if self._done is not None:
            out.append(self._line(self._render_done()))
        else:
            progress = 'files %d/%d' % (self._files_done, self._files_total)
            parts = [self._phase, progress]
            rate = self._rate()
            if rate:
                parts.append(rate)
            out.append(self._line('  '.join(parts)))
        out.append('─' * self.width)
        if self._done is not None:
            out.extend(self._render_tiers())
        else:
            out.append(self._line('channels %d  (tier 要等扫完才定)' % len(self._channels)))
            for name, tier in self._channels[-self.max_rows:]:
                glyph, code = tier_glyph(tier)
                out.append(self._line('  %s %s' % (
                    colorize(glyph, code, self.use_color), name)))
        return '\n'.join(out)

    def _render_done(self):
        done = self._done or {}
        return 'done  %d channels  %d sinks  %d unresolved' % (
            done.get('channels') or 0, done.get('sinks') or 0,
            done.get('unresolved') or 0)

    def _render_tiers(self):
        done = self._done or {}
        by_tier = done.get('by_tier') or {}
        rows = []
        # 按「硬结论在前」排，借来档垫底：排序本身也是一种分层表达
        order = ('direct', 'name_confirmed', 'chain', 'ambiguous', 'ast_only')
        for tier in order:
            count = by_tier.get(tier)
            if not count:
                continue
            glyph, code = tier_glyph(tier)
            mark = ' 借来' if tier in BORROWED_TIERS else ''
            rows.append(self._line('  %s %-16s %3d%s' % (
                colorize(glyph, code, self.use_color), tier, count, mark)))
        return rows

    def paint(self):
        """把当前状态打到流上。清屏 + 重绘，光标回到左上。"""
        if self.stream is None:
            return
        text = self.render()
        try:
            self.stream.write('\033[2J\033[H' + text + '\n')
            self.stream.flush()
        except (OSError, ValueError):
            pass


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


# ---------------------------------------------------------------- Web 呈现
# 零依赖：http.server + 线程 + queue。前端是单个 HTML，原生 JS + EventSource，
# 不引任何 CDN（离线可用，也没有供应链风险）。

_DASHBOARD = """<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<title>ipcsurface live</title>
<style>
body{font:13px/1.5 ui-monospace,Consolas,monospace;background:#111;color:#ddd;margin:0;padding:14px}
h1{font-size:13px;font-weight:600;margin:0 0 6px}
.bar{color:#888}
table{border-collapse:collapse;width:100%;margin-top:10px}
td,th{padding:2px 8px;text-align:left;border-bottom:1px solid #222}
th{color:#888;font-weight:400}
.hard{color:#4caf50}.chain{color:#ffb300}.borrowed{color:#777}.unknown{color:#777}
</style></head><body>
<h1>ipcsurface live <span id="input" class="bar"></span></h1>
<div class="bar" id="head">等事件…</div>
<table><thead><tr><th>档</th><th>通道</th><th>tier</th></tr></thead>
<tbody id="rows"></tbody></table>
<script>
var glyph={direct:['þ','hard'],name_confirmed:['þ','hard'],chain:['◐','chain'],
           ambiguous:['¨','borrowed'],ast_only:['¨','borrowed']};
var rows=new Map();
function addCh(name,tier){
  if(rows.has(name))return;
  var g=glyph[tier]||['·','unknown'];
  var tr=document.createElement('tr');
  tr.innerHTML='<td class="'+g[1]+'">'+g[0]+'</td><td>'+name+'</td><td class="'+g[1]+'">'+(tier||'—')+'</td>';
  rows.set(name,tr);
  document.getElementById('rows').appendChild(tr);
}
function head(t){document.getElementById('head').textContent=t;}
function onEvent(ev){
  var p=ev.payload||{};
  if(ev.kind==='lifecycle'&&p.stage==='start'){document.getElementById('input').textContent=p.input||'';}
  if(ev.kind==='discovery'){addCh(p.name,p.tier);}
  if(ev.kind==='progress'){head('files '+p.files_done+'/'+p.files_total+'  '+Math.round((p.elapsed_ms||0)/1000)+'s');}
  if(ev.kind==='lifecycle'&&p.stage==='done'){head('done  '+p.channels+' channels  '+p.sinks+' sinks  '+p.unresolved+' unresolved');}
}
fetch('/api/snapshot').then(function(r){return r.json();}).then(function(s){
  if(s.input){document.getElementById('input').textContent=s.input;}
  (s.channels||[]).forEach(function(c){addCh(c,s.tiers?s.tiers[c]:null);});
  if(s.done){head('done  '+s.done.channels+' channels  '+s.done.sinks+' sinks');}
  var es=new EventSource('/events');
  ['lifecycle','progress','discovery','stats'].forEach(function(k){
    es.addEventListener(k,function(e){onEvent(JSON.parse(e.data));});
  });
});
</script></body></html>
"""


class _Handler(__import__('http.server', fromlist=['BaseHTTPRequestHandler']).BaseHTTPRequestHandler):
    """单页 + SSE + 快照 + 导出。零依赖，全部 GET。"""

    server_version = 'ipcsurface-live'

    def log_message(self, *args):
        pass   # 别把访问日志刷到用户屏幕上

    def _send(self, code, ctype, body, extra=None):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        state = self.server.state
        path = self.path.split('?', 1)[0]
        if path == '/':
            self._send(200, 'text/html; charset=utf-8', _DASHBOARD)
        elif path == '/api/snapshot':
            self._send(200, 'application/json; charset=utf-8',
                       json.dumps(state.snapshot(), ensure_ascii=False))
        elif path == '/api/export':
            body = '\n'.join(json.dumps(e, ensure_ascii=False,
                                        separators=(',', ':'))
                             for e in state.events)
            self._send(200, 'application/x-ndjson; charset=utf-8',
                       body + ('\n' if body else ''))
        elif path == '/events':
            self._stream(state)
        else:
            self._send(404, 'text/plain; charset=utf-8', 'not found\n')

    def _stream(self, state):
        """SSE：先补发历史（按 Last-Event-ID 断线续传），再挂着等新事件。"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'keep-alive')
        self.end_headers()

        last_id = 0
        header = self.headers.get('Last-Event-ID')
        if header:
            try:
                last_id = int(header)
            except ValueError:
                last_id = 0

        box = state.subscribe(last_id)
        try:
            while True:
                try:
                    event = box.get(timeout=15)
                except Exception:   # queue.Empty
                    self.wfile.write(b': keepalive\n\n')
                    self.wfile.flush()
                    continue
                if event is None:
                    break
                frame = 'id: %d\nevent: %s\ndata: %s\n\n' % (
                    event.get('seq', 0), event.get('kind', 'message'),
                    json.dumps(event, ensure_ascii=False))
                self.wfile.write(frame.encode('utf-8'))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            state.unsubscribe(box)


class _State:
    """服务端状态：所有事件 + 每个 SSE 连接一个队列。"""

    def __init__(self, max_events=50000, queue_size=2000):
        self.max_events = max_events
        self.queue_size = queue_size
        self._events = []
        self._subs = []
        self._lock = __import__('threading').Lock()

    @property
    def events(self):
        with self._lock:
            return list(self._events)

    def record(self, event):
        """EventBus 的订阅者。必须快：扫描线程上同步调用。"""
        import queue as _queue
        with self._lock:
            self._events.append(event)
            if len(self._events) > self.max_events:
                del self._events[:len(self._events) - self.max_events]
            subs = list(self._subs)
        for box in subs:
            try:
                box.put_nowait(event)
            except _queue.Full:
                pass   # 慢客户端：丢给它，不拖累扫描

    def subscribe(self, last_id=0):
        import queue as _queue
        box = _queue.Queue(maxsize=self.queue_size)
        with self._lock:
            # 补发：把 last_id 之后的事件先灌进队列（再挂新的）
            for event in self._events:
                if event.get('seq', 0) > last_id:
                    try:
                        box.put_nowait(event)
                    except _queue.Full:
                        break
            self._subs.append(box)
        return box

    def unsubscribe(self, box):
        with self._lock:
            if box in self._subs:
                self._subs.remove(box)

    def snapshot(self):
        """当前状态：用于刷新页面后立即恢复，不用等重放。"""
        with self._lock:
            events = list(self._events)
        channels = []
        tiers = {}
        seen = set()
        done = None
        input_name = None
        s = {'channels': [], 'tiers': {}, 'done': None, 'input': None}
        for event in events:
            kind = event.get('kind')
            payload = event.get('payload') or {}
            if kind == 'lifecycle' and payload.get('stage') == 'start':
                input_name = payload.get('input')
            elif kind == 'discovery':
                name = payload.get('name')
                if name and name not in seen:
                    seen.add(name)
                    channels.append(name)
                    tiers[name] = payload.get('tier')
            elif kind == 'lifecycle' and payload.get('stage') == 'done':
                done = payload
                # done 里带「每条通道的代表档」：discovery 当时 tier 还是 None
                # （sink 分析没跑完），到这一步才定下来。缺了这段，页面就只能画横线。
                for ch, tier in (payload.get('channel_tiers') or {}).items():
                    if ch not in seen:
                        seen.add(ch)
                        channels.append(ch)
                    tiers[ch] = tier
        s['channels'] = channels
        s['tiers'] = tiers
        s['done'] = done
        s['input'] = input_name
        return s

    def summary_line(self):
        snap = self.snapshot()
        return '%d 条事件，%d 条通道' % (len(self.events), len(snap['channels']))


class EventServer:
    """把一个 EventBus 挂到 HTTP 上：/ 是页面，/events 是 SSE，/api/snapshot 是快照。"""

    def __init__(self, bus, host='127.0.0.1', port=8080, max_events=50000):
        import http.server
        import threading
        self.bus = bus
        self.host = host
        self.port = port
        self.state = _State(max_events=max_events)
        bus.add_listener(self.state.record)
        self._httpd = http.server.ThreadingHTTPServer((host, port), _Handler)
        self._httpd.state = self.state
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]   # port=0 时拿真实端口
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        name='ipcsurface-live', daemon=True)

    @property
    def url(self):
        return 'http://%s:%d/' % (self.host, self.port)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        try:
            self._httpd.shutdown()
        except Exception:  # noqa: BLE001
            pass
        try:
            self._httpd.server_close()
        except Exception:  # noqa: BLE001
            pass

    def serve_forever(self):
        """前台跑（扫描完想留页面给用户看时用）。"""
        try:
            self._httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
