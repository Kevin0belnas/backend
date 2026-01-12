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
| CORS CONFIGURATION - UPDATED FOR NEW BACKEND DOMAIN
|--------------------------------------------------------------------------
| DEV:
|   - localhost / LAN IPs
|
| PROD:
|   - https://fulfill1st.com (frontend)
|   - https://backend.fulfill1st.com (backend itself)
*/
app.use(cors({
  origin: [
    'http://192.168.68.13:5177', // DEV (LAN)
    'http://localhost:5177',     // DEV (local)
    'https://fulfill1st.com',    // PROD Frontend
    'https://backend.fulfill1st.com' // PROD Backend (for self-calls if needed)
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Handle preflight requests
app.options('*', cors());

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
| ADD DEBUG ENDPOINTS FOR TESTING
|--------------------------------------------------------------------------
*/
// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    server: 'Fulfill1st Backend',
    domain: 'backend.fulfill1st.com',
    port: PORT,
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Simple test endpoint
app.get('/api/test', (req, res) => {
  res.json({
    success: true,
    message: 'Backend is working!',
    backendDomain: 'backend.fulfill1st.com',
    allowedOrigins: ['https://fulfill1st.com'],
    cors: 'enabled'
  });
});

// Log requests for debugging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url} - Origin: ${req.headers.origin || 'none'}`);
  next();
});

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
| ROOT ENDPOINT
|--------------------------------------------------------------------------
*/
app.get('/', (req, res) => {
  res.json({
    message: 'Fulfill1st Backend API',
    domain: 'backend.fulfill1st.com',
    status: 'running',
    endpoints: {
      health: '/api/health',
      test: '/api/test',
      bookstores: '/api/bookstores'
    },
    frontend: 'https://fulfill1st.com'
  });
});

/*
|--------------------------------------------------------------------------
| 404 HANDLER
|--------------------------------------------------------------------------
*/
app.use((req, res) => {
  res.status(404).json({
    error: 'Route not found',
    path: req.url,
    method: req.method,
    backend: 'backend.fulfill1st.com',
    suggestion: 'Try /api/health or /api/test'
  });
});

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
    console.log(`
===========================================
🚀 BACKEND SERVER RUNNING
===========================================
Domain: https://backend.fulfill1st.com
Port: ${PORT}
Environment: production

Frontend: https://fulfill1st.com
API Base: https://backend.fulfill1st.com/api

Test endpoints:
1. https://backend.fulfill1st.com/api/health
2. https://backend.fulfill1st.com/api/test
3. https://backend.fulfill1st.com/api/bookstores
===========================================
`);
  } else {
    console.log(`
===========================================
🚀 DEV SERVER RUNNING
===========================================
Local: http://localhost:${PORT}
API Base: http://localhost:${PORT}/api

Test endpoints:
1. http://localhost:${PORT}/api/health
2. http://localhost:${PORT}/api/test
===========================================
`);
  }
});