const { app, BrowserWindow, ipcMain } = require('electron');

// 故意把通道名算出来，看工具认不认得
function makeChannel(rest) {
  return 'ledger:' + rest;
}

const OPS = ['add', 'list', 'remove'];

app.whenReady().then(() => {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      preload: __dirname + '/preload.js',
      contextIsolation: true,
      nodeIntegration: false
    }
  });
  win.loadFile('index.html');
});

for (const op of OPS) {
  ipcMain.handle(makeChannel(op), (event, payload) => ({ ok: true, op }));
}

ipcMain.handle('ledger:' + 'shadow', () => ({ ok: true }));
ipcMain.handle(`ledger:${'tpl'}`, () => ({ ok: true }));

ipcMain.handle('ledger:clear', () => ({ ok: true }));
