require('dotenv').config();
const path = require('path');
const { createApp } = require('./app');

const PORT = Number(process.env.PORT) || 5344;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'vaultly.db');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';

const app = createApp({ dbPath: DB_PATH, setupPassword: ADMIN_PASSWORD });

app.listen(PORT, () => {
  console.log(`Vaultly listening on http://localhost:${PORT}`);
  if (ADMIN_PASSWORD === 'admin') {
    console.log('⚠ Using default setup password — set ADMIN_PASSWORD in .env before exposing this publicly.');
  }
});
