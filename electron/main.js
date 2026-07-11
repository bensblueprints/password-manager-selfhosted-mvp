// Desktop mode: boots the same zero-knowledge Express server on a free local
// port with data in Electron's userData dir, and opens a window pointing at it.
// NOTE: unlike other OneTime Suite apps there is no auto-login here — Vaultly is
// end-to-end encrypted, so your master password is always required to unlock.
const { app, BrowserWindow, shell } = require('electron');
const path = require('path');

let win;

app.whenReady().then(() => {
  const dataDir = path.join(app.getPath('userData'), 'data');

  const { createApp } = require(path.join(__dirname, '..', 'server', 'app.js'));
  const server = createApp({
    dbPath: path.join(dataDir, 'vaultly.db'),
    // Desktop is single-machine: the bootstrap setup password defaults to
    // 'vaultly' locally (only gates FIRST account creation, not the vault).
    setupPassword: process.env.ADMIN_PASSWORD || 'vaultly'
  });

  const listener = server.listen(0, '127.0.0.1', () => {
    const port = listener.address().port;
    win = new BrowserWindow({
      width: 1320,
      height: 880,
      autoHideMenuBar: true,
      backgroundColor: '#09090b',
      title: 'Vaultly',
      webPreferences: { contextIsolation: true, nodeIntegration: false }
    });
    win.webContents.setWindowOpenHandler(({ url }) => {
      shell.openExternal(url);
      return { action: 'deny' };
    });
    win.loadURL(`http://127.0.0.1:${port}/`);
  });

  app.on('window-all-closed', () => {
    listener.close();
    app.quit();
  });
});
