const { app, BrowserWindow, ipcMain } = require('electron');
const { VAULT_UNLOCK_CHANNEL, VAULT_EXPORT_CHANNEL } = require('./channels');

app.whenReady().then(() => {
  new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: { contextIsolation: true, nodeIntegration: false }
  }).loadFile('index.html');
});

ipcMain.handle(VAULT_UNLOCK_CHANNEL, (event, payload) => ({ ok: true }));
ipcMain.handle(VAULT_EXPORT_CHANNEL, () => null);
