const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('nativeLedger', {
  sum: (payload) => ipcRenderer.invoke('native:sum', payload),
  info: () => ipcRenderer.invoke('native:info')
});
