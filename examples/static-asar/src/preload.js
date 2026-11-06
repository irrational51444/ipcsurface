const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('ledger', {
  add: (payload) => ipcRenderer.invoke('ledger:add', payload),
  list: () => ipcRenderer.invoke('ledger:list'),
  remove: (id) => ipcRenderer.invoke('ledger:remove', id),
  exportFile: () => ipcRenderer.invoke('ledger:export'),
  sync: (token) => ipcRenderer.invoke('ledger:__internal_sync', token)
});
