"""最小成本的 attach 探测：连上 Electron 主进程的 inspector，问三个问题。

不是全量探针。只回答「值不值得投入做定向探针」：
1. inspector 端口连得上吗？
2. 连上的是不是**主进程**（`process.argv` 里有目标 exe、`process.type` 是 browser）？
3. `require('electron').ipcMain` 拿得到吗？拿得到就能挂 `handle` 记录调用。

全都不需要第三方库：WebSocket 握手和帧是手写的。

用法：
    python scripts/probe_attach.py --port 9232
"""
import argparse
import base64
import json
import os
import socket
import struct
import sys
import urllib.request


def http_targets(port, timeout=4):
    """GET /json，拿 inspector 的目标列表。"""
    url = 'http://127.0.0.1:%d/json' % port
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8', 'replace'))


class WS:
    """够用的最小 WebSocket 客户端：只做文本帧。"""

    def __init__(self, url, timeout=10):
        rest = url.split('://', 1)[1]
        host_port, _, path = rest.partition('/')
        host, _, port = host_port.partition(':')
        self.sock = socket.create_connection((host, int(port or 80)), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = ('GET /%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\n'
               'Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n'
               'Sec-WebSocket-Version: 13\r\n\r\n' % (path, host_port, key))
        self.sock.sendall(req.encode())
        buf = b''
        while b'\r\n\r\n' not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError('握手时连接断了')
            buf += chunk
        if b' 101 ' not in buf.split(b'\r\n', 1)[0]:
            raise ConnectionError('握手被拒：' + buf.split(b'\r\n', 1)[0].decode('latin-1'))

    def send(self, text):
        payload = text.encode()
        mask = os.urandom(4)
        header = bytearray([0x81])
        ln = len(payload)
        if ln < 126:
            header.append(0x80 | ln)
        elif ln < 65536:
            header.append(0x80 | 126)
            header += struct.pack('>H', ln)
        else:
            header.append(0x80 | 127)
            header += struct.pack('>Q', ln)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def _read_n(self, n):
        buf = b''
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError('读帧时连接断了')
            buf += chunk
        return buf

    def recv(self):
        b1, b2 = self._read_n(2)
        ln = b2 & 0x7F
        if ln == 126:
            ln = struct.unpack('>H', self._read_n(2))[0]
        elif ln == 127:
            ln = struct.unpack('>Q', self._read_n(8))[0]
        if b2 & 0x80:
            mask = self._read_n(4)
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(self._read_n(ln)))
        else:
            data = self._read_n(ln)
        return data.decode('utf-8', 'replace')

    def call(self, msg_id, method, params=None):
        self.send(json.dumps({'id': msg_id, 'method': method, 'params': params or {}}))
        while True:
            data = json.loads(self.recv())
            if data.get('id') == msg_id:
                return data

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def evaluate(ws, msg_id, expression):
    """执行一句 JS，返回值。失败返回 (None, 错误)。"""
    resp = ws.call(msg_id, 'Runtime.evaluate',
                   {'expression': expression, 'returnByValue': True, 'awaitPromise': True})
    if 'error' in resp:
        return None, resp['error'].get('message', str(resp['error']))
    result = resp.get('result', {})
    if result.get('exceptionDetails'):
        return None, str(result['exceptionDetails'].get('text', '异常'))
    return result.get('result', {}).get('value'), None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--port', type=int, default=9232)
    args = ap.parse_args()

    print('1) 拿 inspector 目标 ...')
    try:
        targets = http_targets(args.port)
    except Exception as exc:  # noqa: BLE001
        print('   连不上：%s' % exc)
        print('   结论：inspector 不可用（端口没开 / 被拦）')
        return 2
    print('   目标 %d 个' % len(targets))
    for t in targets:
        print('   - title=%s type=%s' % (t.get('title'), t.get('type')))
    if not targets:
        return 2

    ws_url = targets[0].get('webSocketDebuggerUrl')
    if not ws_url:
        print('   目标里没有 webSocketDebuggerUrl，连不了')
        return 2

    print('2) WebSocket 连上去 ...')
    try:
        ws = WS(ws_url)
    except Exception as exc:  # noqa: BLE001
        print('   连不上：%s' % exc)
        return 2
    try:
        ws.call(1, 'Runtime.enable')
        # --inspect-brk 启动的进程会停在第一行，先放行才能 evaluate
        ws.call(2, 'Runtime.runIfWaitingForDebugger')
        print('3) 问三个问题 ...')
        info, err = evaluate(ws, 3, 'JSON.stringify({'
                                     'argv: typeof process === "object" ? process.argv : null, '
                                     'ptype: typeof process === "object" ? process.type : null, '
                                     'versions: typeof process === "object" ? process.versions : null, '
                                     'title: typeof process === "object" ? process.title : null})')
        if err:
            print('   取进程信息失败：%s' % err)
        else:
            print('   进程信息：%s' % info)
            try:
                data = json.loads(info)
            except TypeError:
                data = {}
            argv = data.get('argv') or []
            is_main = data.get('ptype') == 'browser' or any('bilibili' in str(a).lower()
                                                           or '哔哩' in str(a) for a in argv)
            print('   像主进程：%s' % ('是' if is_main else '不确定'))

        ipc, err = evaluate(ws, 4,
                            '(() => { try { if (typeof require !== "function") '
                            'return "no-require"; const e = require("electron"); '
                            'if (!e || !e.ipcMain) return "no-ipcMain"; '
                            'return JSON.stringify({hasOn: typeof e.ipcMain.on === "function", '
                            'hasHandle: typeof e.ipcMain.handle === "function"}); } '
                            'catch (e) { return "ERR:" + e.message; } })()')
        print('   require("electron").ipcMain：%s' % (ipc if not err else 'ERR:' + err))
    finally:
        ws.close()

    print()
    print('结论：能 attach 就值得做定向探针；连不上或没有 ipcMain，就是「探针不可用」。')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
