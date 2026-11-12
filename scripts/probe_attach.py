"""attach 探测：连 Electron 主进程的 CDP 端口，最小成本判断「能不能挂上去」。

这是一个**资产**，不是一次性脚本。手写 WebSocket、纯标准库、零依赖——它证明了
「动态能力零依赖」这条路的第一层（连 CDP）是可行的。

## 能做什么

- 连接 inspector/CDP 端口（`http://127.0.0.1:<port>/json` 拿目标，WebSocket 连上去）
- 枚举 target（title / type / webSocketDebuggerUrl）
- 执行 `Runtime.evaluate`，读 `process.argv` / `process.type` / `process.versions`
- 判断 `require('electron').ipcMain` 在不在——在，就能挂 `handle`/`on` 记录调用

## 不能做什么

- **绕过启动器**：如果 exe 是启动器、`--inspect-brk` 被它消费掉，attach 到的只是启动器层
- **穿透加密壳**：目标代码加密在别的文件里（如 `.biliapp`），连上了也读不到明文
- 不判断「有没有漏洞」，只判断「能不能连上、连上的是谁」

## 这次在 bilibili 上遇到了什么（2026-11-12，1.17.2）

- 不带参数启动：进程 1.5 秒退出，无输出
- `--inspect-brk=PORT`：端口开了、能连上
- 但 target 是 `title=C:_Windows_..._powershell.exe[...]`，**启动器层**
- `process` 为 `null`，`require` 不存在（`no-require`）
- 结论：`--inspect-brk` 被启动器消费，**未触及 Electron 主进程** → 探针不可用

换一个「没有启动器拦截」的目标（自己打包的 Electron 应用、或启动器不消费 `--inspect-brk`
的应用），这个脚本就能用。下次遇到同类目标，先跑它，别直接上全量探针。

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
        print('3) 等 process 注入，然后问三个问题 ...')

        # 放行后 process/require 不是立刻就有；轮询而不是死等，抓到就走。
        # 有些目标（抖音那种带启动器的）窗口很短，慢一步就换 target 了。
        import time as _time
        info, err, data = None, None, {}
        for _attempt in range(20):
            _time.sleep(0.3)
            info, err = evaluate(ws, 3, 'JSON.stringify({'
                                         'argv: typeof process === "object" ? process.argv : null, '
                                         'ptype: typeof process === "object" ? process.type : null, '
                                         'versions: typeof process === "object" ? process.versions : null, '
                                         'title: typeof process === "object" ? process.title : null})')
            if err:
                continue
            try:
                data = json.loads(info) if info else {}
            except (TypeError, ValueError):
                data = {}
            if data.get('argv'):
                break
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
