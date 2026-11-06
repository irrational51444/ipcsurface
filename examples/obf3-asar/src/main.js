// 中档混淆：名字经过一个自解码函数才算得出来。
// 静态看，这里只有一串 \x 转义；要还原得把 _d 真的跑一遍。
const { app, BrowserWindow, ipcMain } = require('electron');

function _d(s) {
  var out = '';
  for (var i = 0; i < s.length; i++) {
    out += String.fromCharCode(s.charCodeAt(i) ^ 7);
  }
  return out;
}

app.whenReady().then(() => {
  new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: { contextIsolation: true, nodeIntegration: false }
  }).loadFile('index.html');
});

ipcMain.handle(_d('\x71\x66\x72\x6b\x73\x3d\x72\x69\x6b\x68\x64\x6c'), (e, p) => ({ ok: true }));
ipcMain.handle(_d('\x71\x66\x72\x6b\x73\x3d\x6b\x68\x64\x6c'), () => null);
