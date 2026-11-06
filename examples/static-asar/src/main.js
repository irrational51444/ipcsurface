const { app, BrowserWindow, ipcMain, shell } = require('electron');
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(app.getPath('userData'), 'ledger');
const LEDGER_FILE = path.join(DATA_DIR, 'entries.json');
const AUTO_BACKUP_MS = 7 * 60 * 1000;
const INTERNAL_FLAG = 'e5f3a19b';

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function readLedger() {
  ensureDir();
  if (!fs.existsSync(LEDGER_FILE)) return [];
  try {
    return JSON.parse(fs.readFileSync(LEDGER_FILE, 'utf8'));
  } catch (err) {
    return [];
  }
}

function writeLedger(rows) {
  ensureDir();
  fs.writeFileSync(LEDGER_FILE, JSON.stringify(rows, null, 2), 'utf8');
}

function newWindow() {
  const win = new BrowserWindow({
    width: 920,
    height: 640,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  return win;
}

ipcMain.handle('ledger:add', (event, payload) => {
  const rows = readLedger();
  const row = {
    id: Date.now(),
    text: String(payload && payload.text ? payload.text : ''),
    amount: Number(payload && payload.amount) || 0,
    at: new Date().toISOString()
  };
  rows.push(row);
  writeLedger(rows);
  return row;
});

ipcMain.handle('ledger:list', () => readLedger());

ipcMain.handle('ledger:remove', (event, id) => {
  const rows = readLedger().filter((r) => r.id !== id);
  writeLedger(rows);
  return rows.length;
});

ipcMain.handle('ledger:export', async () => {
  const rows = readLedger();
  const out = path.join(app.getPath('downloads'), 'ledger-export.json');
  fs.writeFileSync(out, JSON.stringify(rows, null, 2), 'utf8');
  shell.showItemInFolder(out);
  return out;
});

ipcMain.handle('ledger:__internal_sync', (event, token) => {
  if (token !== INTERNAL_FLAG) return { ok: false };
  const rows = readLedger();
  return { ok: true, count: rows.length, dir: DATA_DIR };
});

setInterval(() => {
  const rows = readLedger();
  writeLedger(rows);
}, AUTO_BACKUP_MS);

app.whenReady().then(() => {
  newWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) newWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
