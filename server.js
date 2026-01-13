// Minimal working server.js (Hostinger-safe)
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
*/
const PORT = process.env.PORT || 3000;

/*
|--------------------------------------------------------------------------
| TRUST PROXY (REQUIRED FOR HOSTINGER)
|--------------------------------------------------------------------------
*/
app.set('trust proxy', 1);

/*
|--------------------------------------------------------------------------
| SESSION CONFIGURATION
|--------------------------------------------------------------------------
*/
app.use(session({
  secret: process.env.SESSION_SECRET || 'bookstore-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

/*
|--------------------------------------------------------------------------
| CORS CONFIGURATION
|--------------------------------------------------------------------------
*/
app.use(cors({
  origin: [
    'http://192.168.68.13:5177',
    'http://localhost:5177',
    'https://fulfill1st.com',
    'https://backend.fulfill1st.com'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// ❌ REMOVED: app.options('*', cors());
// ✔ CHANGE: Hostinger + Express can crash on wildcard OPTIONS.
// ✔ CORS middleware already handles OPTIONS automatically.

app.use(express.json());

/*
|--------------------------------------------------------------------------
| DATABASE CONNECTION TEST (SAFE MODE)
|--------------------------------------------------------------------------
*/
// ❌ BEFORE: testConnection();
// ✔ CHANGE: Prevent Hostinger from killing the app if DB fails on startup
(async () => {
  try {
    await testConnection();
    console.log('✅ Database connected');
  } catch (err) {
    console.error('❌ Database connection failed:', err.message);
  }
})();

/*
|--------------------------------------------------------------------------
| STATIC FILES
|--------------------------------------------------------------------------
*/
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

/*
|--------------------------------------------------------------------------
| DEBUG ENDPOINTS
|--------------------------------------------------------------------------
*/
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

app.get('/api/test', (req, res) => {
  res.json({
    success: true,
    message: 'Backend is working!',
    backendDomain: 'backend.fulfill1st.com',
    allowedOrigins: ['https://fulfill1st.com'],
    cors: 'enabled'
  });
});

/*
|--------------------------------------------------------------------------
| REQUEST LOGGING
|--------------------------------------------------------------------------
*/
app.use((req, res, next) => {
  console.log(
    `${new Date().toISOString()} - ${req.method} ${req.url} - Origin: ${req.headers.origin || 'none'}`
  );
  next();
});

/*
|--------------------------------------------------------------------------
| API ROUTES
|--------------------------------------------------------------------------
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
*/
// ❌ BEFORE: app.listen(PORT, '0.0.0.0', ...)
// ✔ CHANGE: Hostinger binds automatically; simpler & safer
app.listen(PORT, () => {
  console.log(`
===========================================
🚀 BACKEND SERVER RUNNING
===========================================
Domain: https://backend.fulfill1st.com
Port: ${PORT}
Environment: ${process.env.NODE_ENV || 'development'}
API Base: https://backend.fulfill1st.com/api
===========================================
`);
});
