// 名字全提到数组里，代码里只按下标取。这是混淆里最常见、也最浅的一层。
const { app, BrowserWindow, ipcMain } = require('electron');

var _0x4a2f = ['vault:unlock', 'vault:lock', 'vault:__export_all', 'vault:status'];
var _0x1b2c = ['width', 'height', 'webPreferences'];

app.whenReady().then(() => {
  var opts = {};
  opts[_0x1b2c[0]] = 900;
  opts[_0x1b2c[1]] = 640;
  opts[_0x1b2c[2]] = { contextIsolation: true, nodeIntegration: false };
  const win = new BrowserWindow(opts);
  win.loadFile('index.html');
});

ipcMain.handle(_0x4a2f[0], (event, payload) => ({ ok: true }));
ipcMain.handle(_0x4a2f[1], () => ({ ok: true }));
ipcMain.handle(_0x4a2f[2], () => null);
ipcMain.handle(_0x4a2f[3], () => ({ ok: true }));
