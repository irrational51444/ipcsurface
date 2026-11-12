"""用 CDP 断点抓 Electron 主进程的运行时上下文 —— 比「放行后立刻问」靠谱。

为什么需要这个：`--inspect-brk` 停在 `electron/js2c/browser_init` 时，那个 context 里
**`process` 是 null**（Node 全局还没建起来）；一放行，context 又被销毁
（`Cannot find context with specified id`）。两条路都拿不到 `ipcMain`。

换一条：先在用户代码（`app.asar` 里的 .js）上下断点，再放行。
断点触发时进程已经跑起来了，`process`/`require` 都在，这时候问才有答案。

用法：
    python scripts/probe_breakpoint.py --port 9260 [--url-regex "app\\.asar.*index\\.js"]
"""
import argparse
import json
import socket
import sys

# 脚本目录本身就在 sys.path[0]，probe_attach 是同目录的模块，直接 import
import probe_attach as pa  # noqa: E402


def recv_event(ws, timeout=15):
    """带超时读一条 CDP 消息；超时返回 None。"""
    ws.sock.settimeout(timeout)
    try:
        return json.loads(ws.recv())
    except socket.timeout:
        return None
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--port', type=int, default=9260)
    ap.add_argument('--url-regex', default=r'app\.asar.*\.js',
                    help='在哪些 URL 上下断点，默认 app.asar 里的所有 .js')
    ap.add_argument('--wait', type=float, default=20.0, help='等断点触发的最长秒数')
    args = ap.parse_args()

    targets = pa.http_targets(args.port)
    if not targets:
        print('没有 target，端口连不上')
        return 2
    print('target: %s' % targets[0].get('title'))

    ws = pa.WS(targets[0]['webSocketDebuggerUrl'])
    try:
        ws.call(1, 'Runtime.enable')
        ws.call(2, 'Debugger.enable')
        bp = ws.call(3, 'Debugger.setBreakpointByUrl', {
            'urlRegex': args.url_regex, 'lineNumber': 0, 'columnNumber': 0})
        locs = bp.get('result', {}).get('locations') or []
        print('断点已设（urlRegex=%s），预解析到 %d 处' % (args.url_regex, len(locs)))
        for loc in locs[:5]:
            print('   %s:%s' % (loc.get('scriptId'), loc.get('lineNumber')))

        # 放行：进程继续启动，撞到断点就停
        ws.call(4, 'Runtime.runIfWaitingForDebugger')
        print('已放行，等断点触发（最多 %.0f 秒）...' % args.wait)

        ws.sock.settimeout(1.0)
        deadline_events = 0
        paused = None
        while deadline_events < int(args.wait):
            evt = recv_event(ws, timeout=1.0)
            if not evt:
                deadline_events += 1
                continue
            method = evt.get('method')
            if method == 'Debugger.paused':
                paused = evt.get('params') or {}
                frames = paused.get('callFrames') or []
                print('断住了：%d 个调用帧，reason=%s' % (len(frames), paused.get('reason')))
                if frames:
                    print('   顶帧：%s @ %s' % (frames[0].get('functionName'),
                                               (frames[0].get('url') or '')[-80:]))
                break
            if method == 'Debugger.scriptParsed':
                continue

        if not paused:
            print('等了 %.0f 秒没撞到断点（可能这个包不加载 app.asar 里的 js）' % args.wait)
            return 3

        frames = paused.get('callFrames') or []
        if not frames:
            print('暂停了但没有调用帧')
            return 3
        frame_id = frames[0]['callFrameId']

        def on_frame(msg_id, expr):
            resp = ws.call(msg_id, 'Debugger.evaluateOnCallFrame', {
                'callFrameId': frame_id, 'expression': expr,
                'returnByValue': True, 'silent': True})
            res = resp.get('result', {})
            if res.get('exceptionDetails'):
                return None, str(res['exceptionDetails'].get('text', '异常'))
            return res.get('result', {}).get('value'), None

        print()
        print('在断点帧上问：')
        for i, expr in enumerate([
            'typeof process',
            'typeof process === "object" ? String(process.type) : "no"',
            'typeof process === "object" ? JSON.stringify(process.argv) : "no"',
            'typeof require',
            '(() => { try { const e = require("electron"); if (!e || !e.ipcMain) '
            'return "no-ipcMain"; return JSON.stringify({on: typeof e.ipcMain.on, '
            'handle: typeof e.ipcMain.handle}); } catch (err) { return "ERR:" + err.message; } })()',
        ], start=10):
            value, err = on_frame(i, expr)
            print('   %-70s -> %r %s' % (expr, value, err or ''))

        ws.call(20, 'Debugger.resume')
    finally:
        ws.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
