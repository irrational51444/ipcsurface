#!/usr/bin/env node
/**
 * 运行时探针：把 Electron 应用跑起来，从主进程的调试口里捞出真正注册过的通道。
 *
 * 静态分析猜不出来的东西，这里不用猜——程序自己会把它注册过的名字报出来。
 *
 * 用法:
 *   node run.js <未打包的应用目录> [等待秒数]
 *
 * 只读。不写目标、不改目标、不发任何通道消息。
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
const inspectPort = 9229;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function getJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (err) {
          reject(err);
        }
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
    } catch (err) {
      // 还没起来
    }
    await sleep(300);
  }
  throw new Error('调试口没开');
}

function evaluate(ws, expression) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 1e9);
    const timer = setTimeout(() => reject(new Error('evaluate 超时')), 8000);
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

// 主进程里问三件事：注册了哪些通道、窗口开了几扇、谁挂了 preload
const QUERY = `(() => {
  const out = { handlers: [], listeners: [], windows: [] };
  try {
    // 调试上下文里没有 require，借主模块的
    const req = (typeof require === 'function')
      ? require
      : (process.mainModule || module).require.bind(process.mainModule || module);
    const { ipcMain, BrowserWindow } = req('electron');
    if (ipcMain && ipcMain._invokeHandlers && ipcMain._invokeHandlers.forEach) {
      ipcMain._invokeHandlers.forEach((_fn, name) => out.handlers.push(name));
    }
    const anyIpc = ipcMain && ipcMain._events;
    if (anyIpc) {
      for (const key of Object.keys(anyIpc)) {
        if (key !== 'newListener' && key !== 'removeListener') out.listeners.push(key);
      }
    }
    if (BrowserWindow && BrowserWindow.getAllWindows) {
      for (const win of BrowserWindow.getAllWindows()) {
        const prefs = (win.webContents && win.webContents.getLastWebPreferences)
          ? win.webContents.getLastWebPreferences() : {};
        out.windows.push({
          preload: prefs && prefs.preload ? String(prefs.preload) : null,
          contextIsolation: prefs ? prefs.contextIsolation : null,
          nodeIntegration: prefs ? prefs.nodeIntegration : null,
          sandbox: prefs ? prefs.sandbox : null,
        });
      }
    }
  } catch (err) {
    return JSON.stringify({ error: String(err) });
  }
  return JSON.stringify(out);
})()`;

(async () => {
  const env = { ...process.env };
  delete env.ELECTRON_RUN_AS_NODE; // 否则会被当成普通 node 跑
  // 单实例锁是按 userData 目录加的。用默认目录的话，目标应用只要已经在跑，
  // 第二个进程就会把锁让出去然后自己退出，调试口还没等我们连上就没了。
  // 给它一份独立的目录，锁就落在别处，进程能老老实实起来。
  const userData = process.argv[4] || fs.mkdtempSync(path.join(os.tmpdir(), 'probe-userdata-'));
  const child = spawn(electron, [
    `--inspect=${inspectPort}`,
    '--remote-debugging-port=0',
    `--user-data-dir=${userData}`,
    target,
  ], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env,
  });
  let stderr = '';
  child.stderr.on('data', (c) => (stderr += c));

  let report;
  try {
    const wsUrl = await waitForInspector(15000);
    const ws = new WebSocket(wsUrl);
    await new Promise((resolve, reject) => {
      ws.once('open', resolve);
      ws.once('error', reject);
    });
    await sleep(waitSeconds * 1000); // 让应用把自己的通道注册完
    const result = await evaluate(ws, QUERY);
    ws.close();
    if (!result || !result.result) throw new Error('拿不到结果');
    report = JSON.parse(result.result.value);
  } catch (err) {
    report = { error: String(err.message || err), stderr };
  } finally {
    try {
      child.kill();
    } catch (err) {
      // 已经没了
    }
  }

  console.log(JSON.stringify(report, null, 2));
})();
