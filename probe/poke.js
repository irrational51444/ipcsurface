#!/usr/bin/env node
/**
 * 动态那一步：跑起来，往每条通道真的发一条消息，看它怎么接。
 *
 * run.js 读的是登记表——程序说他注册了哪些通道。
 * 这个脚本更进一步：挨个敲一遍，记下谁崩了、谁没做检查。
 *
 * 只对自己的靶子或明确授权的程序用。它会真的执行目标里的代码。
 *
 * 用法:
 *   node poke.js <未打包的应用目录> [等待秒数]
 */
const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');
const electron = require('electron');
const WebSocket = require('ws');

const target = path.resolve(process.argv[2] || '.');
const waitSeconds = Number(process.argv[3] || 6);
const inspectPort = 9230;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function getJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => {
        try { resolve(JSON.parse(body)); } catch (err) { reject(err); }
      });
    }).on('error', reject);
  });
}

async function waitForInspector(timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const list = await getJson(`http://127.0.0.1:${inspectPort}/json/list`);
      if (list && list.length && list[0].webSocketDebuggerUrl) return list[0].webSocketDebuggerUrl;
    } catch (err) { /* 还没起来 */ }
    await sleep(300);
  }
  throw new Error('调试口没开');
}

function evaluate(ws, expression) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 1e9);
    const timer = setTimeout(() => reject(new Error('evaluate 超时')), 20000);
    const onMessage = (raw) => {
      const msg = JSON.parse(raw);
      if (msg.id !== id) return;
      clearTimeout(timer);
      ws.off('message', onMessage);
      if (msg.error) return reject(new Error(JSON.stringify(msg.error)));
      resolve(msg.result);
    };
    ws.on('message', onMessage);
    ws.send(JSON.stringify({
      id,
      method: 'Runtime.evaluate',
      params: { expression, returnByValue: true, awaitPromise: true },
    }));
  });
}

// 三种不合规的输入，挨个通道敲一遍。真崩了就是真崩了。
const POKE = `(async () => {
  const req = (typeof require === 'function')
    ? require
    : (process.mainModule || module).require.bind(process.mainModule || module);
  const { ipcMain, BrowserWindow } = req('electron');
  const out = [];
  const names = [];
  if (ipcMain && ipcMain._invokeHandlers && ipcMain._invokeHandlers.forEach) {
    ipcMain._invokeHandlers.forEach((_fn, name) => names.push(name));
  }
  const win = BrowserWindow.getAllWindows()[0];
  const fakeEvent = win && win.webContents ? { sender: win.webContents, senderFrame: null } : {};
  const payloads = [
    { label: 'undefined', value: undefined },
    { label: '空对象', value: {} },
    { label: '超长字符串', value: 'A'.repeat(100000) },
    { label: 'null', value: null },
  ];
  for (const name of names) {
    const handler = ipcMain._invokeHandlers.get(name);
    if (typeof handler !== 'function') continue;
    for (const p of payloads) {
      const row = { channel: name, payload: p.label, ok: true };
      try {
        const r = await handler(fakeEvent, p.value);
        row.result = typeof r === 'object' && r !== null
          ? JSON.stringify(r).slice(0, 60) : String(r).slice(0, 60);
      } catch (err) {
        row.ok = false;
        row.error = String(err && err.message ? err.message : err).slice(0, 120);
      }
      out.push(row);
    }
  }
  return JSON.stringify(out);
})()`;

(async () => {
  const env = { ...process.env };
  delete env.ELECTRON_RUN_AS_NODE;
  // 和 run.js 一样：锁按 userData 目录加，目标已经开着的话第二个进程会自己退出。
  const userData = process.argv[4] || fs.mkdtempSync(path.join(os.tmpdir(), 'poke-userdata-'));
  const child = spawn(electron, [`--inspect=${inspectPort}`, `--user-data-dir=${userData}`, target], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env,
  });
  let report;
  try {
    const wsUrl = await waitForInspector(15000);
    const ws = new WebSocket(wsUrl);
    await new Promise((resolve, reject) => {
      ws.once('open', resolve);
      ws.once('error', reject);
    });
    await sleep(waitSeconds * 1000);
    const result = await evaluate(ws, POKE);
    ws.close();
    report = JSON.parse(result.result.value);
  } catch (err) {
    report = { error: String(err.message || err) };
  } finally {
    try { child.kill(); } catch (err) { /* 已经没了 */ }
  }
  console.log(JSON.stringify(report, null, 2));
})();
