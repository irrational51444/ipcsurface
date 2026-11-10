// 运行时探针：把 Electron 真的注册了哪些 IPC 名字记下来。
//
// 为什么需要它：静态看不到运行时拼出来的名字（`ipcMain.handle(x.channel, …)`）。
// 这份脚本挂进主进程（`--require ./probe_preload.js` 或打包时塞进 preload 路径），
// 把每次注册写成一行 JSONL，交给 ipcsurface 的 --runtime 吃。
//
// 只记录，不拦截、不改参数：拿到的名字是「真的注册了」，
// 但仍不能证明门后逻辑安全——那份报告里写得清楚。
const fs = require('fs');
const path = require('path');

const OUT = process.env.IPCSURFACE_PROBE_OUT
  || path.join(process.cwd(), 'ipc-probe.jsonl');

// 第一行就写一条：证明探针真的被加载了。
// 没有这一条、后面也没有注册记录时，能立刻分清是「没加载」还是「没注册」。
function boot() {
  try {
    fs.appendFileSync(OUT, JSON.stringify({ kind: 'probe-loaded', pid: process.pid }) + '\n');
  } catch (err) {}
}
boot();

function write(record) {
  try {
    fs.appendFileSync(OUT, JSON.stringify(record) + '\n');
  } catch (err) {
    // 探针自己不能把主程序拖死
  }
}

function site() {
  const stack = (new Error().stack || '').split('\n').slice(3, 5).join(' | ');
  return stack.replace(/\\/g, '/').slice(0, 400);
}

try {
  const electron = require('electron');
  const ipcMain = electron && electron.ipcMain;
  if (ipcMain) {
    ['handle', 'handleOnce', 'on', 'once'].forEach((method) => {
      const original = ipcMain[method];
      if (typeof original !== 'function') return;
      ipcMain[method] = function patched(channel, ...rest) {
        write({
          kind: method,
          channel: typeof channel === 'string' ? channel : String(channel),
          type: typeof channel,
          site: site(),
        });
        return original.apply(this, [channel, ...rest]);
      };
    });
  }
} catch (err) {
  write({ kind: 'probe-error', error: String(err && err.message || err) });
}

module.exports = { out: OUT };
