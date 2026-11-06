const { contextBridge, ipcRenderer } = require('electron');

const PREFIX = 'ledger:';

contextBridge.exposeInMainWorld('ledger', {
  raw: (name, payload) => ipcRenderer.invoke(PREFIX + name, payload),
  fixed: () => ipcRenderer.invoke('ledger:clear')
});
