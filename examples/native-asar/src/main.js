const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');

// 挂一个 native 模块。真项目里这里是 C++ 写的 .node，
// 越界、泄漏、重复释放只可能出在这种地方，不在 JS 那层。
let ledger = null;
try {
  ledger = require('./native/ledger.node');
} catch (err) {
  ledger = null;
}

app.whenReady().then(() => {
  const win = new BrowserWindow({
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });
  win.loadFile(path.join(__dirname, 'index.html'));
});

ipcMain.handle('native:sum', (event, payload) => {
  if (!ledger) return { ok: false, reason: 'addon missing' };
  return { ok: true, total: ledger.sum(payload) };
});

ipcMain.handle('native:info', () => ({ ok: true, loaded: Boolean(ledger) }));
