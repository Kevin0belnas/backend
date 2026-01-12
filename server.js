// Minimal working server.js
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const routes = require('./routes');
const { testConnection } = require('./db');
const path = require('path');

const app = express();

/*
|--------------------------------------------------------------------------
| PORT
|--------------------------------------------------------------------------
| DEV:
|   You usually run on 3000 locally
|
| PROD (Hostinger):
|   Hostinger provides the PORT automatically via process.env.PORT
*/
const PORT = process.env.PORT || 3000;

/*
|--------------------------------------------------------------------------
| TRUST PROXY
|--------------------------------------------------------------------------
| PROD ONLY:
|   Required on Hostinger so secure cookies & sessions work correctly
*/
app.set('trust proxy', 1);

/*
|--------------------------------------------------------------------------
| SESSION CONFIGURATION
|--------------------------------------------------------------------------
| DEV:
|   - secure: false (HTTP)
|
| PROD:
|   - secure: true (HTTPS)
|   - sameSite: 'none' (cross-origin)
*/
app.use(session({
  secret: process.env.SESSION_SECRET || 'bookstore-secret-key', // DEV fallback
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // PROD ONLY
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

/*
|--------------------------------------------------------------------------
| CORS CONFIGURATION
|--------------------------------------------------------------------------
| DEV:
|   - localhost / LAN IPs
|
| PROD:
|   - https://fulfill1st.com ONLY
*/
app.use(cors({
  origin: [
    'http://192.168.68.13:5177', // DEV (LAN)
    'http://localhost:5177',     // DEV (local)
    'https://fulfill1st.com'     // PROD
  ],
  credentials: true
}));

app.use(express.json());

/*
|--------------------------------------------------------------------------
| DATABASE CONNECTION TEST
|--------------------------------------------------------------------------
| DEV & PROD:
|   Safe to run once on startup
*/
testConnection();

/*
|--------------------------------------------------------------------------
| STATIC FILES (UPLOADS)
|--------------------------------------------------------------------------
| DEV & PROD:
|   Used for serving uploaded images/files
*/
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

/*
|--------------------------------------------------------------------------
| API ROUTES
|--------------------------------------------------------------------------
| DEV & PROD:
|   All backend endpoints live under /api
*/
app.use('/api', routes);

/*
|--------------------------------------------------------------------------
| FRONTEND SERVING
|--------------------------------------------------------------------------
| DEV:
|   ❌ Not used (Vite runs separately)
|
| PROD:
|   ❌ NOT USED because frontend (dist) is already uploaded to Hostinger
|   (Kept here for reference only)
|
| Uncomment ONLY if you decide to serve React from Express in the future
*/
// if (process.env.NODE_ENV === 'production') {
//   app.use(express.static(path.join(__dirname, '../frontend/build')));
//   app.get('*', (req, res) => {
//     res.sendFile(path.join(__dirname, '../frontend/build', 'index.html'));
//   });
// }

/*
|--------------------------------------------------------------------------
| START SERVER
|--------------------------------------------------------------------------
| DEV:
|   Logs localhost or LAN IP
|
| PROD:
|   Hostinger handles the domain & port
*/
app.listen(PORT, '0.0.0.0', () => {
  if (process.env.NODE_ENV === 'production') {
    console.log('Backend running on fulfill1st.com');
  } else {
    console.log(`DEV server running on http://localhost:${PORT}`);
  }
});
