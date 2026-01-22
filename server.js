const express = require('express');
const cors = require('cors');
const session = require('express-session');
const { pool, testConnection } = require('./db');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

/*
|--------------------------------------------------------------------------
| PORT
|--------------------------------------------------------------------------
*/
const PORT = process.env.PORT || 3000;

/*
|--------------------------------------------------------------------------
| DEVELOPMENT MODE SETTINGS
|--------------------------------------------------------------------------
*/
const isDevelopment = process.env.NODE_ENV !== 'production';

/*
|--------------------------------------------------------------------------
| SESSION CONFIGURATION (DEVELOPMENT MODE)
|--------------------------------------------------------------------------
*/
app.use(session({
  secret: process.env.SESSION_SECRET || 'bookstore-dev-secret-key',
  resave: false,
  saveUninitialized: true, // Changed to true for development
  cookie: {
    secure: false, // Changed to false for development
    sameSite: 'lax', // Changed to lax for development
    maxAge: 24 * 60 * 60 * 1000
  }
}));

/*
|--------------------------------------------------------------------------
| CORS CONFIGURATION (DEVELOPMENT MODE)
|--------------------------------------------------------------------------
*/
// Development CORS settings - more permissive
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin && isDevelopment) return callback(null, true);
    
    const allowedOrigins = [
      'http://192.168.68.4:5177', // Your LAN IP for development
      'http://localhost:5177',     // Localhost for development
      'http://localhost:5173',     // Additional local port
      'http://127.0.0.1:5177',     // Localhost IP
      'http://127.0.0.1:5173',      // Additional local port
      'https://fulfill1st.com',
      'https://api.fulfill1st.com'
    ];
    
    if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else {
      console.warn(`CORS blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));

app.use(express.json());

/*
|--------------------------------------------------------------------------
| DATABASE CONNECTION TEST
|--------------------------------------------------------------------------
*/
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
// Ensure uploads directory exists
const uploadDirs = ['uploads', 'uploads/bookstores', 'uploads/books', 'uploads/social-media', 'uploads/events'];
uploadDirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

/*
|--------------------------------------------------------------------------
| AUTHENTICATION MIDDLEWARE
|--------------------------------------------------------------------------
*/
const requireAuth = (req, res, next) => {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.status(401).json({ success: false, error: 'Authentication required' });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.session && req.session.userId && req.session.role === 'admin') {
    next();
  } else {
    res.status(403).json({ success: false, error: 'Admin access required' });
  }
};

/*
|--------------------------------------------------------------------------
| DEVELOPMENT MIDDLEWARE
|--------------------------------------------------------------------------
*/
if (isDevelopment) {
  // Detailed request logging for development
  app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    const method = req.method.padEnd(7);
    const url = req.url;
    const origin = req.headers.origin || 'no-origin';
    const userAgent = req.headers['user-agent'] || 'no-user-agent';
    
    console.log(`\n🌐 ${timestamp} - ${method} ${url}`);
    console.log(`   Origin: ${origin}`);
    console.log(`   User-Agent: ${userAgent.substring(0, 50)}...`);
    console.log(`   Session ID: ${req.sessionID}`);
    console.log(`   Authenticated: ${!!req.session.userId}`);
    
    // Log request body for non-GET requests (except large uploads)
    if (req.method !== 'GET' && req.body && Object.keys(req.body).length > 0) {
      console.log('   Body:', JSON.stringify(req.body, null, 2).substring(0, 200));
    }
    
    next();
  });

  // Development-only endpoints
  app.get('/api/dev/session', (req, res) => {
    res.json({
      session: req.session,
      sessionID: req.sessionID,
      cookies: req.cookies,
      headers: {
        origin: req.headers.origin,
        host: req.headers.host,
        'user-agent': req.headers['user-agent']
      }
    });
  });

  app.get('/api/dev/env', (req, res) => {
    res.json({
      environment: process.env.NODE_ENV || 'development',
      nodeVersion: process.version,
      platform: process.platform,
      memoryUsage: process.memoryUsage(),
      uptime: process.uptime(),
      port: PORT,
      isDevelopment: isDevelopment
    });
  });
}

/*
|--------------------------------------------------------------------------
| DEBUG ENDPOINTS
|--------------------------------------------------------------------------
*/
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    server: 'Fulfill1st Development Backend',
    domain: 'Local Development',
    port: PORT,
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    mode: isDevelopment ? 'Development' : 'Production',
    frontend: 'http://192.168.68.4:5177'
  });
});

app.get('/api/test', (req, res) => {
  res.json({
    success: true,
    message: 'Backend is working!',
    mode: isDevelopment ? 'Development' : 'Production',
    allowedOrigins: [
      'http://192.168.68.4:5177',
      'http://localhost:5177',
      'http://localhost:5173'
    ],
    cors: 'enabled',
    session: req.session ? 'Active' : 'No session',
    timestamp: new Date().toISOString()
  });
});

// Add this after your existing /api/test endpoint
app.get('/api/db-test', async (req, res) => {
  console.log('🔍 Testing database connection...');
  
  try {
    // Test 1: Basic connection
    const connection = await pool.getConnection();
    console.log('✅ Database connection established');
    
    // Test 2: Simple query
    const [result] = await connection.query('SELECT 1 + 1 as solution');
    console.log('✅ Simple query executed:', result);
    
    // Test 3: Check if bookstores table exists
    const [tables] = await connection.query(
      "SHOW TABLES LIKE 'bookstores'"
    );
    
    connection.release();
    
    res.json({
      success: true,
      message: 'Database connection successful',
      mode: 'Development',
      database: {
        connection: 'OK',
        simpleQuery: result[0].solution === 2 ? 'OK' : 'FAILED',
        bookstoresTableExists: tables.length > 0,
        tablesFound: tables
      },
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ Database test failed:', error.message);
    
    res.status(500).json({
      success: false,
      error: 'Database connection failed',
      mode: 'Development',
      details: {
        message: error.message,
        code: error.code,
        errno: error.errno,
        sqlState: error.sqlState
      },
      suggestion: 'Check database credentials and connection',
      timestamp: new Date().toISOString()
    });
  }
});

/*
|--------------------------------------------------------------------------
| AUTH ROUTES
|--------------------------------------------------------------------------
*/

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (email === 'admin@bookstore.com' && password === 'admin123') {
      req.session.userId = 1;
      req.session.email = email;
      req.session.role = 'admin';
      req.session.name = 'Admin User';
      
      if (isDevelopment) {
        console.log('🔑 Login successful for:', email);
        console.log('   Session created:', req.sessionID);
      }
      
      res.json({
        success: true,
        user: {
          id: 1,
          email: email,
          name: 'Admin User',
          role: 'admin'
        }
      });
    } else {
      if (isDevelopment) {
        console.log('❌ Login failed for:', email);
      }
      res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Logout
app.post('/api/logout', (req, res) => {
  const sessionId = req.sessionID;
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ success: false, error: 'Logout failed' });
    }
    
    if (isDevelopment) {
      console.log('👋 Logout successful. Session destroyed:', sessionId);
    }
    
    res.json({ success: true, message: 'Logged out successfully' });
  });
});

// Check auth status
app.get('/api/auth/check', (req, res) => {
  if (req.session.userId) {
    res.json({
      success: true,
      user: {
        id: req.session.userId,
        email: req.session.email,
        name: req.session.name,
        role: req.session.role
      }
    });
  } else {
    res.json({ success: false, user: null });
  }
});

// Development login endpoint (for testing)
if (isDevelopment) {
  app.post('/api/dev/login-as', (req, res) => {
    const { role } = req.body;
    
    if (role === 'admin') {
      req.session.userId = 1;
      req.session.email = 'admin@bookstore.com';
      req.session.role = 'admin';
      req.session.name = 'Admin User';
    } else if (role === 'user') {
      req.session.userId = 2;
      req.session.email = 'user@bookstore.com';
      req.session.role = 'user';
      req.session.name = 'Regular User';
    }
    
    res.json({
      success: true,
      message: `Logged in as ${role}`,
      user: {
        id: req.session.userId,
        email: req.session.email,
        name: req.session.name,
        role: req.session.role
      }
    });
  });
}

/*
|--------------------------------------------------------------------------
| ADMIN DASHBOARD ROUTES
|--------------------------------------------------------------------------
*/

// Admin dashboard stats
app.get('/api/admin/dashboard', requireAdmin, async (req, res) => {
  try {
    const [bookstoreCount] = await pool.query('SELECT COUNT(*) as count FROM bookstores');
    const [authorCount] = await pool.query('SELECT COUNT(*) as count FROM authors');
    const [bookCount] = await pool.query('SELECT COUNT(*) as count FROM books');
    const [recentBookstores] = await pool.query(
      'SELECT * FROM bookstores ORDER BY created_at DESC LIMIT 5'
    );
    
    res.json({
      success: true,
      data: {
        stats: {
          bookstores: bookstoreCount[0].count,
          authors: authorCount[0].count,
          books: bookCount[0].count
        },
        recentBookstores: recentBookstores
      }
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

/*
|--------------------------------------------------------------------------
| BOOKSTORE ROUTES
|--------------------------------------------------------------------------
*/

// GET all bookstores
app.get('/api/bookstores', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM bookstores ORDER BY created_at DESC');
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching bookstores:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET single bookstore by ID
app.get('/api/bookstores/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const [bookstoreRows] = await pool.query('SELECT * FROM bookstores WHERE id = ?', [id]);
    
    if (bookstoreRows.length === 0) {
      return res.status(404).json({ success: false, error: 'Bookstore not found' });
    }
    
    const bookstore = bookstoreRows[0];
    
    // Get authors for this bookstore
    const [authorRows] = await pool.query('SELECT * FROM authors WHERE bookstore_id = ?', [id]);
    
    // Get books for this bookstore
    const [bookRows] = await pool.query(`
      SELECT b.*, a.name as author_name 
      FROM books b 
      JOIN authors a ON b.author_id = a.id 
      WHERE b.bookstore_id = ?
    `, [id]);
    
    res.json({
      success: true,
      data: {
        ...bookstore,
        authors: authorRows,
        books: bookRows
      }
    });
  } catch (error) {
    console.error('Error fetching bookstore:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Configure multer for file upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/bookstores';
    
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `bookstore-${uniqueSuffix}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|webp|svg/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (extname && mimetype) {
    return cb(null, true);
  } else {
    cb(new Error('Only image files are allowed (jpeg, jpg, png, gif, webp, svg)'));
  }
};

const upload = multer({ 
  storage, 
  fileFilter,
  limits: { fileSize: 10 * 1024 * 1024 }
});

// Enhanced POST route with better error handling
app.post('/api/bookstores', requireAdmin, (req, res, next) => {
  upload.single('image')(req, res, function(err) {
    if (err) {
      console.error('Multer error:', err.message);
      
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({ 
            success: false, 
            error: 'File size too large. Maximum size is 10MB.' 
          });
        }
      }
      
      if (err.message.includes('Only image files')) {
        return res.status(400).json({ 
          success: false, 
          error: err.message 
        });
      }
      
      return res.status(500).json({ 
        success: false, 
        error: 'File upload failed' 
      });
    }
    
    createBookstore(req, res);
  });
});

async function createBookstore(req, res) {
  try {
    const {
      name,
      location,
      address = '',
      established = null,
      description = '',
      email = '',
      phone = '',
      website = '',
      logo = '📚',
      category = 'Independent',
      rating = 0,
      reviews = 0
    } = req.body;

    // Clean the established field - convert empty string to null
    const cleanEstablished = established === '' ? null : parseInt(established);
    
    // Clean the rating and reviews fields
    const cleanRating = rating === '' ? 0 : parseInt(rating);
    const cleanReviews = reviews === '' ? 0 : parseInt(reviews);
    
    // Clean the phone field
    const cleanPhone = phone.trim();

    // Get uploaded file path (if any)
    const imageUrl = req.file ? `/uploads/bookstores/${req.file.filename}` : null;

    const [result] = await pool.query(
      `INSERT INTO bookstores 
      (name, location, address, established, description, email, phone, website, logo, category, rating, reviews, image_url) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        name, 
        location, 
        address, 
        cleanEstablished,
        description, 
        email, 
        cleanPhone,
        website, 
        logo, 
        category, 
        cleanRating,
        cleanReviews,
        imageUrl
      ]
    );

    const newBookstore = {
      id: result.insertId,
      name,
      location,
      address,
      established: cleanEstablished,
      description,
      email,
      phone: cleanPhone,
      website,
      logo,
      category,
      rating: cleanRating,
      reviews: cleanReviews,
      image_url: imageUrl
    };

    res.status(201).json({ 
      success: true, 
      data: newBookstore,
      message: 'Bookstore created successfully'
    });
  } catch (error) {
    console.error('Error creating bookstore:', error);
    
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error('Error deleting uploaded file:', err);
      });
    }
    
    res.status(500).json({ success: false, error: error.message });
  }
}

// PUT update bookstore (protected - admin only)
app.put('/api/bookstores/:id', requireAdmin, (req, res, next) => {
  upload.single('image')(req, res, function(err) {
    if (err) {
      console.error('Multer error:', err.message);
      
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({ 
            success: false, 
            error: 'File size too large. Maximum size is 10MB.' 
          });
        }
      }
      
      if (err.message.includes('Only image files')) {
        return res.status(400).json({ 
          success: false, 
          error: err.message 
        });
      }
      
      return res.status(500).json({ 
        success: false, 
        error: 'File upload failed' 
      });
    }
    
    updateBookstore(req, res);
  });
});

async function updateBookstore(req, res) {
  try {
    const { id } = req.params;
    const updateData = {};
    
    // Add all text fields from req.body
    Object.keys(req.body).forEach(key => {
      if (req.body[key] !== undefined && req.body[key] !== '') {
        // Clean specific fields
        if (key === 'established') {
          updateData[key] = req.body[key] === '' ? null : parseInt(req.body[key]);
        } else if (key === 'rating' || key === 'reviews') {
          updateData[key] = req.body[key] === '' ? 0 : parseInt(req.body[key]);
        } else if (key === 'phone') {
          updateData[key] = req.body[key].trim();
        } else {
          updateData[key] = req.body[key];
        }
      }
    });
    
    // Handle uploaded file
    if (req.file) {
      updateData.image_url = `/uploads/bookstores/${req.file.filename}`;
      
      // Optional: Delete old image file
      try {
        const [existingRows] = await pool.query('SELECT image_url FROM bookstores WHERE id = ?', [id]);
        if (existingRows.length > 0 && existingRows[0].image_url) {
          const oldImagePath = `uploads/bookstores/${existingRows[0].image_url.split('/').pop()}`;
          fs.unlink(oldImagePath, (err) => {
            if (err && err.code !== 'ENOENT') {
              console.error('Error deleting old image:', err);
            }
          });
        }
      } catch (err) {
        console.error('Error deleting old image:', err);
      }
    }
    
    // If no fields to update
    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({ success: false, error: 'No fields to update' });
    }
    
    const fields = Object.keys(updateData);
    const values = Object.values(updateData);
    
    const setClause = fields.map(field => `${field} = ?`).join(', ');
    const query = `UPDATE bookstores SET ${setClause} WHERE id = ?`;
    
    await pool.query(query, [...values, id]);
    
    res.json({ success: true, message: 'Bookstore updated successfully' });
  } catch (error) {
    console.error('Error updating bookstore:', error);
    
    // Delete uploaded file if error occurred
    if (req.file) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error('Error deleting uploaded file:', err);
      });
    }
    
    res.status(500).json({ success: false, error: error.message });
  }
}

// DELETE bookstore (protected - admin only)
app.delete('/api/bookstores/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    await pool.query('DELETE FROM bookstores WHERE id = ?', [id]);
    
    res.json({ success: true, message: 'Bookstore deleted successfully' });
  } catch (error) {
    console.error('Error deleting bookstore:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

/*
|--------------------------------------------------------------------------
| AUTHOR ROUTES
|--------------------------------------------------------------------------
*/

// GET all authors (for admin panel)
app.get('/api/authors', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT a.*, b.name as bookstore_name 
      FROM authors a 
      LEFT JOIN bookstores b ON a.bookstore_id = b.id 
      ORDER BY a.created_at DESC
    `);
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching all authors:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET author by ID
app.get('/api/authors/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const [authorRows] = await pool.query('SELECT * FROM authors WHERE id = ?', [id]);
    
    if (authorRows.length === 0) {
      return res.status(404).json({ success: false, error: 'Author not found' });
    }
    
    const author = authorRows[0];
    
    // Get books for this author
    const [bookRows] = await pool.query(`
      SELECT b.*, a.name as author_name 
      FROM books b 
      JOIN authors a ON b.author_id = a.id 
      WHERE b.author_id = ?
    `, [id]);
    
    res.json({
      success: true,
      data: {
        ...author,
        books: bookRows
      }
    });
  } catch (error) {
    console.error('Error fetching author:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET author's books (for the modal in frontend)
app.get('/api/authors/:id/books', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Check if author exists
    const [authorRows] = await pool.query('SELECT id, name FROM authors WHERE id = ?', [id]);
    if (authorRows.length === 0) {
      return res.status(404).json({ success: false, error: 'Author not found' });
    }
    
    const author = authorRows[0];
    
    // Get books for this author
    const [bookRows] = await pool.query(`
      SELECT b.*, a.name as author_name 
      FROM books b 
      JOIN authors a ON b.author_id = a.id 
      WHERE b.author_id = ?
      ORDER BY b.created_at DESC
    `, [id]);
    
    res.json({
      success: true,
      data: {
        author: author,
        books: bookRows
      }
    });
  } catch (error) {
    console.error('Error fetching author books:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// PUT update author
app.put('/api/authors/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { bookstore_id, name, genre, bio, avatar, books_count } = req.body;
    
    // Validate required fields
    if (!bookstore_id || !name) {
      return res.status(400).json({ 
        success: false, 
        error: 'Bookstore ID and author name are required' 
      });
    }
    
    const [result] = await pool.query(
      `UPDATE authors SET 
       bookstore_id = ?, 
       name = ?, 
       genre = ?, 
       bio = ?, 
       avatar = ?, 
       books_count = ? 
       WHERE id = ?`,
      [bookstore_id, name, genre, bio, avatar, books_count, id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Author not found' 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Author updated successfully' 
    });
  } catch (error) {
    console.error('Error updating author:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// DELETE author
app.delete('/api/authors/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const [result] = await pool.query('DELETE FROM authors WHERE id = ?', [id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Author not found' 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Author deleted successfully' 
    });
  } catch (error) {
    console.error('Error deleting author:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET authors by bookstore
app.get('/api/authors/bookstore/:bookstoreId', async (req, res) => {
  try {
    const { bookstoreId } = req.params;
    const [rows] = await pool.query('SELECT * FROM authors WHERE bookstore_id = ?', [bookstoreId]);
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching authors:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST create author (protected - admin only)
app.post('/api/authors', requireAdmin, async (req, res) => {
  try {
    const {
      bookstore_id,
      name,
      genre = '',
      bio = '',
      avatar = '👤',
      books_count = 0
    } = req.body;
    
    // Validate required fields
    if (!bookstore_id || !name) {
      return res.status(400).json({ 
        success: false, 
        error: 'Bookstore ID and author name are required' 
      });
    }
    
    // Check if bookstore exists
    const [bookstoreRows] = await pool.query('SELECT id FROM bookstores WHERE id = ?', [bookstore_id]);
    if (bookstoreRows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Bookstore not found' 
      });
    }
    
    const [result] = await pool.query(
      `INSERT INTO authors (bookstore_id, name, genre, bio, avatar, books_count) 
      VALUES (?, ?, ?, ?, ?, ?)`,
      [bookstore_id, name, genre, bio, avatar, books_count]
    );
    
    const newAuthor = {
      id: result.insertId,
      bookstore_id,
      name,
      genre,
      bio,
      avatar,
      books_count
    };
    
    res.status(201).json({ 
      success: true, 
      data: newAuthor,
      message: 'Author created successfully'
    });
  } catch (error) {
    console.error('Error creating author:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

/*
|--------------------------------------------------------------------------
| BOOK ROUTES
|--------------------------------------------------------------------------
*/

// GET all books (for admin panel)
app.get('/api/books', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT b.*, a.name as author_name, bs.name as bookstore_name 
      FROM books b 
      JOIN authors a ON b.author_id = a.id 
      JOIN bookstores bs ON b.bookstore_id = bs.id 
      ORDER BY b.created_at DESC
    `);
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching all books:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// PUT update book
app.put('/api/books/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { 
      bookstore_id, 
      author_id, 
      title, 
      price, 
      genre, 
      published_date, 
      isbn, 
      description,
      image_url
    } = req.body;
    
    // Validate required fields
    if (!bookstore_id || !author_id || !title) {
      return res.status(400).json({ 
        success: false, 
        error: 'Bookstore ID, author ID, and title are required' 
      });
    }
    
    const [result] = await pool.query(
      `UPDATE books SET 
       bookstore_id = ?, 
       author_id = ?, 
       title = ?, 
       price = ?, 
       genre = ?, 
       published_date = ?, 
       isbn = ?, 
       description = ?,
       image_url = ? 
       WHERE id = ?`,
      [bookstore_id, author_id, title, price, genre, published_date, isbn, description, image_url, id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Book not found' 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Book updated successfully' 
    });
  } catch (error) {
    console.error('Error updating book:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// DELETE book
app.delete('/api/books/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const [result] = await pool.query('DELETE FROM books WHERE id = ?', [id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Book not found' 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Book deleted successfully' 
    });
  } catch (error) {
    console.error('Error deleting book:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET books by bookstore
app.get('/api/books/bookstore/:bookstoreId', async (req, res) => {
  try {
    const { bookstoreId } = req.params;
    const [rows] = await pool.query(`
      SELECT b.*, a.name as author_name 
      FROM books b 
      JOIN authors a ON b.author_id = a.id 
      WHERE b.bookstore_id = ?
    `, [bookstoreId]);
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching books:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET books by author
app.get('/api/books/author/:authorId', async (req, res) => {
  try {
    const { authorId } = req.params;
    const [rows] = await pool.query(`
      SELECT b.*, a.name as author_name 
      FROM books b 
      JOIN authors a ON b.author_id = a.id 
      WHERE b.author_id = ?
    `, [authorId]);
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching books by author:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Configure multer for book image upload
const bookStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/books';
    
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `book-${uniqueSuffix}${ext}`);
  }
});

const bookFileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|webp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (extname && mimetype) {
    return cb(null, true);
  } else {
    cb(new Error('Only image files are allowed (jpeg, jpg, png, gif, webp)'));
  }
};

const uploadBookImage = multer({ 
  storage: bookStorage, 
  fileFilter: bookFileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }
});

// POST route for uploading book images
app.post('/api/books/upload-image', requireAdmin, (req, res, next) => {
  uploadBookImage.single('image')(req, res, function(err) {
    if (err) {
      console.error('Book image upload error:', err.message);
      
      if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(400).json({ 
            success: false, 
            error: 'File size too large. Maximum size is 5MB.' 
          });
        }
      }
      
      if (err.message.includes('Only image files')) {
        return res.status(400).json({ 
          success: false, 
          error: err.message 
        });
      }
      
      return res.status(500).json({ 
        success: false, 
        error: 'File upload failed' 
      });
    }
    
    if (!req.file) {
      return res.status(400).json({ 
        success: false, 
        error: 'No file uploaded' 
      });
    }
    
    res.json({
      success: true,
      data: {
        imageUrl: `/uploads/books/${req.file.filename}`
      },
      message: 'Book image uploaded successfully'
    });
  });
});

// POST create book (protected - admin only)
app.post('/api/books', requireAdmin, async (req, res) => {
  try {
    const {
      bookstore_id,
      author_id,
      title,
      price = 0,
      genre = '',
      published_date = null,
      isbn = '',
      description = ''
    } = req.body;
    
    // Validate required fields
    if (!bookstore_id || !author_id || !title) {
      return res.status(400).json({ 
        success: false, 
        error: 'Bookstore ID, author ID, and title are required' 
      });
    }
    
    // Check if bookstore exists
    const [bookstoreRows] = await pool.query('SELECT id FROM bookstores WHERE id = ?', [bookstore_id]);
    if (bookstoreRows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Bookstore not found' 
      });
    }
    
    // Check if author exists
    const [authorRows] = await pool.query('SELECT id FROM authors WHERE id = ?', [author_id]);
    if (authorRows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Author not found' 
      });
    }
    
    // Check if author belongs to the bookstore
    const [authorBookstoreRows] = await pool.query(
      'SELECT id FROM authors WHERE id = ? AND bookstore_id = ?', 
      [author_id, bookstore_id]
    );
    if (authorBookstoreRows.length === 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'Author does not belong to the selected bookstore' 
      });
    }
    
    const [result] = await pool.query(
      `INSERT INTO books (bookstore_id, author_id, title, price, genre, published_date, isbn, description) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [bookstore_id, author_id, title, price, genre, published_date, isbn, description]
    );
    
    const newBook = {
      id: result.insertId,
      bookstore_id,
      author_id,
      title,
      price,
      genre,
      published_date,
      isbn,
      description
    };
    
    res.status(201).json({ 
      success: true, 
      data: newBook,
      message: 'Book created successfully'
    });
  } catch (error) {
    console.error('Error creating book:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========== SOCIAL MEDIA LINKS ROUTES ==========

// Configure multer for social media links image upload
const socialMediaStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/social-media';
    
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `social-media-${uniqueSuffix}${ext}`);
  }
});

const socialMediaFileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|webp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (extname && mimetype) {
    return cb(null, true);
  } else {
    cb(new Error('Only image files are allowed (jpeg, jpg, png, gif, webp)'));
  }
};

const uploadSocialMedia = multer({ 
  storage: socialMediaStorage, 
  fileFilter: socialMediaFileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// GET all social media links (updated to serve full image URLs)
app.get('/api/social-media-links', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        id,
        author_name as authorName,
        author_email as authorEmail,
        author_image as authorImage,
        platform,
        username,
        url,
        description,
        is_active as isActive,
        created_at as createdAt,
        updated_at as updatedAt
      FROM social_media_links 
      ORDER BY created_at DESC
    `);
    
    // Transform the data to include full URL for images
    const transformedRows = rows.map(row => ({
      ...row,
      authorImage: row.authorImage ? `/uploads/social-media/${row.authorImage}` : null
    }));
    
    res.json(transformedRows);
  } catch (error) {
    console.error('Error fetching social media links:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET single social media link by ID (updated)
app.get('/api/social-media-links/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await pool.query(`
      SELECT 
        id,
        author_name as authorName,
        author_email as authorEmail,
        author_image as authorImage,
        platform,
        username,
        url,
        description,
        is_active as isActive,
        created_at as createdAt,
        updated_at as updatedAt
      FROM social_media_links 
      WHERE id = ?
    `, [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Social media link not found' });
    }
    
    const link = rows[0];
    link.authorImage = link.authorImage ? `/uploads/social-media/${link.authorImage}` : null;
    
    res.json(link);
  } catch (error) {
    console.error('Error fetching social media link:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST create new social media link (UPDATED with Multer)
app.post('/api/social-media-links', uploadSocialMedia.single('authorImage'), async (req, res) => {
  try {
    const {
      authorName,
      authorEmail,
      platform,
      username,
      url,
      description,
      isActive
    } = req.body;

    // Log the request for debugging
    if (isDevelopment) {
      console.log('Social media POST request body:', req.body);
      console.log('Social media POST file:', req.file);
    }

    // Validate required fields
    if (!authorName || !url || !platform) {
      // If there's a file uploaded, remove it
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ error: 'Author name, URL, and platform are required' });
    }

    // Validate URL format
    try {
      new URL(url);
    } catch (err) {
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    const [result] = await pool.query(
      `INSERT INTO social_media_links 
        (author_name, author_email, author_image, platform, username, url, description, is_active) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        authorName,
        authorEmail || null,
        req.file ? req.file.filename : null,
        platform,
        username || null,
        url,
        description || null,
        isActive !== undefined ? (isActive === 'true' || isActive === true) : true
      ]
    );

    // Get the newly created link
    const [newLink] = await pool.query(`
      SELECT 
        id,
        author_name as authorName,
        author_email as authorEmail,
        author_image as authorImage,
        platform,
        username,
        url,
        description,
        is_active as isActive,
        created_at as createdAt,
        updated_at as updatedAt
      FROM social_media_links 
      WHERE id = ?
    `, [result.insertId]);

    const link = newLink[0];
    link.authorImage = link.authorImage ? `/uploads/social-media/${link.authorImage}` : null;

    res.status(201).json(link);
  } catch (error) {
    console.error('Error creating social media link:', error);
    // If there's a file uploaded, remove it on error
    if (req.file) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: error.message });
  }
});

// PUT update social media link (UPDATED with Multer)
app.put('/api/social-media-links/:id', uploadSocialMedia.single('authorImage'), async (req, res) => {
  try {
    const { id } = req.params;
    const {
      authorName,
      authorEmail,
      platform,
      username,
      url,
      description,
      isActive
    } = req.body;

    if (isDevelopment) {
      console.log('Social media PUT request body:', req.body);
      console.log('Social media PUT file:', req.file);
    }

    // Check if link exists
    const [existing] = await pool.query(
      'SELECT id, author_image FROM social_media_links WHERE id = ?', 
      [id]
    );
    
    if (existing.length === 0) {
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(404).json({ error: 'Social media link not found' });
    }

    // Validate required fields
    if (!authorName || !url || !platform) {
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ error: 'Author name, URL, and platform are required' });
    }

    // Validate URL format
    try {
      new URL(url);
    } catch (err) {
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    // Handle image update
    let authorImage = existing[0].author_image;
    
    // If new image uploaded, remove old one and use new one
    if (req.file) {
      // Remove old image if exists
      if (existing[0].author_image) {
        const oldImagePath = path.join('uploads/social-media', existing[0].author_image);
        if (fs.existsSync(oldImagePath)) {
          fs.unlinkSync(oldImagePath);
        }
      }
      authorImage = req.file.filename;
    }

    await pool.query(
      `UPDATE social_media_links 
       SET 
         author_name = ?,
         author_email = ?,
         author_image = ?,
         platform = ?,
         username = ?,
         url = ?,
         description = ?,
         is_active = ?,
         updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [
        authorName,
        authorEmail || null,
        authorImage,
        platform,
        username || null,
        url,
        description || null,
        isActive !== undefined ? (isActive === 'true' || isActive === true) : true,
        id
      ]
    );

    // Get the updated link
    const [updatedLink] = await pool.query(`
      SELECT 
        id,
        author_name as authorName,
        author_email as authorEmail,
        author_image as authorImage,
        platform,
        username,
        url,
        description,
        is_active as isActive,
        created_at as createdAt,
        updated_at as updatedAt
      FROM social_media_links 
      WHERE id = ?
    `, [id]);

    const link = updatedLink[0];
    link.authorImage = link.authorImage ? `/uploads/social-media/${link.authorImage}` : null;

    res.json(link);
  } catch (error) {
    console.error('Error updating social media link:', error);
    if (req.file) {
      fs.unlinkSync(req.file.path);
    }
    res.status(500).json({ error: error.message });
  }
});

// DELETE social media link (UPDATED with image cleanup)
app.delete('/api/social-media-links/:id', async (req, res) => {
  try {
    const { id } = req.params;

    // Check if link exists and get image path
    const [existing] = await pool.query(
      'SELECT id, author_image FROM social_media_links WHERE id = ?', 
      [id]
    );
    
    if (existing.length === 0) {
      return res.status(404).json({ error: 'Social media link not found' });
    }

    // Delete associated image if exists
    if (existing[0].author_image) {
      const imagePath = path.join('uploads/social-media', existing[0].author_image);
      if (fs.existsSync(imagePath)) {
        fs.unlinkSync(imagePath);
      }
    }

    await pool.query('DELETE FROM social_media_links WHERE id = ?', [id]);
    
    res.json({ success: true, message: 'Social media link deleted successfully' });
  } catch (error) {
    console.error('Error deleting social media link:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET social media links by author name (updated)
app.get('/api/social-media-links/author/:name', async (req, res) => {
  try {
    const { name } = req.params;
    const [rows] = await pool.query(
      `SELECT 
        id,
        author_name as authorName,
        author_email as authorEmail,
        author_image as authorImage,
        platform,
        username,
        url,
        description,
        is_active as isActive,
        created_at as createdAt
      FROM social_media_links 
      WHERE author_name LIKE ? AND is_active = TRUE
      ORDER BY platform`,
      [`%${name}%`]
    );
    
    // Transform the data to include full URL for images
    const transformedRows = rows.map(row => ({
      ...row,
      authorImage: row.authorImage ? `/uploads/social-media/${row.authorImage}` : null
    }));
    
    res.json(transformedRows);
  } catch (error) {
    console.error('Error fetching social media links by author:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET social media links by platform (updated)
app.get('/api/social-media-links/platform/:platform', async (req, res) => {
  try {
    const { platform } = req.params;
    const [rows] = await pool.query(
      `SELECT 
        id,
        author_name as authorName,
        author_email as authorEmail,
        author_image as authorImage,
        platform,
        username,
        url,
        description,
        is_active as isActive,
        created_at as createdAt
      FROM social_media_links 
      WHERE platform = ? AND is_active = TRUE
      ORDER BY author_name`,
      [platform]
    );
    
    // Transform the data to include full URL for images
    const transformedRows = rows.map(row => ({
      ...row,
      authorImage: row.authorImage ? `/uploads/social-media/${row.authorImage}` : null
    }));
    
    res.json(transformedRows);
  } catch (error) {
    console.error('Error fetching social media links by platform:', error);
    res.status(500).json({ error: error.message });
  }
});

// PATCH update link status (active/inactive)
app.patch('/api/social-media-links/:id/status', async (req, res) => {
  try {
    const { id } = req.params;
    const { isActive } = req.body;

    if (typeof isActive !== 'boolean') {
      return res.status(400).json({ error: 'isActive must be a boolean value' });
    }

    await pool.query(
      'UPDATE social_media_links SET is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [isActive, id]
    );

    res.json({ success: true, message: `Link ${isActive ? 'activated' : 'deactivated'} successfully` });
  } catch (error) {
    console.error('Error updating link status:', error);
    res.status(500).json({ error: error.message });
  }
});

// Add static file serving for social media uploads
app.use('/uploads/social-media', express.static('uploads/social-media'));


// ========== EVENT ROUTES ==========
// ========== DISPLAY EVENTS ENDPOINT ==========

// GET events for display (public frontend)
app.get('/api/events-display', async (req, res) => {
  try {
    const { 
      search, 
      eventType, 
      showPast = 'false',
      limit = 50,
      page = 1 
    } = req.query;
    
    console.log('📋 Fetching display events with filters:', {
      search, eventType, showPast, limit, page
    });
    
    let query = `
      SELECT 
        e.id,
        e.title,
        e.start_date,
        e.end_date,
        e.author_name,
        e.bookstore_location,
        e.address,
        e.description,
        e.featured_books,
        e.event_type,
        e.status,
        e.featured,
        e.gallery_images,
        e.created_at,
        e.updated_at,
        COALESCE(COUNT(er.id), 0) as attendees_count
      FROM events e
      LEFT JOIN event_registrations er ON e.id = er.event_id 
        AND er.status IN ('pending', 'confirmed')
      WHERE 1=1
    `;
    
    const params = [];
    
    // Add filters
    if (search) {
      query += ' AND (e.title LIKE ? OR e.author_name LIKE ? OR e.bookstore_location LIKE ? OR e.description LIKE ?)';
      const searchParam = `%${search}%`;
      params.push(searchParam, searchParam, searchParam, searchParam);
    }
    
    if (eventType && eventType !== 'all') {
      query += ' AND e.event_type = ?';
      params.push(eventType);
    }
    
    // Show past events or only upcoming
    if (showPast === 'false') {
      const now = new Date().toISOString().split('T')[0];
      query += ' AND (e.status IN ("Upcoming", "Ongoing") OR (e.status IS NULL AND e.start_date >= ?))';
      params.push(now);
    }
    
    // Add GROUP BY for the COUNT() function
    query += ' GROUP BY e.id';
    
    // Add sorting - featured and upcoming first
    query += ' ORDER BY e.featured DESC, e.start_date ASC, e.created_at DESC';
    
    // Add pagination
    if (limit && page) {
      const offset = (parseInt(page) - 1) * parseInt(limit);
      query += ' LIMIT ? OFFSET ?';
      params.push(parseInt(limit), offset);
    }
    
    console.log('📝 Executing display query:', query.substring(0, 200) + '...');
    console.log('🔢 With params:', params);
    
    const [rows] = await pool.query(query, params);
    
    // Helper function to format image URLs
    const formatImageUrls = (imagePath) => {
      if (!imagePath) return [];
      
      // If it's already a full array with URLs
      if (Array.isArray(imagePath)) {
        return imagePath.map(img => {
          if (img.startsWith('http')) return img;
          if (img.startsWith('/uploads/')) return img;
          return `/uploads/events/${img}`;
        });
      }
      
      // If it's a string, try to parse JSON or handle as string
      if (typeof imagePath === 'string') {
        try {
          const parsed = JSON.parse(imagePath);
          if (Array.isArray(parsed)) {
            return parsed.map(img => {
              if (img.startsWith('http')) return img;
              if (img.startsWith('/uploads/')) return img;
              return `/uploads/events/${img}`;
            });
          }
          return [`/uploads/events/${parsed}`];
        } catch (error) {
          // Not JSON, treat as string
          if (imagePath.startsWith('http')) return [imagePath];
          if (imagePath.startsWith('/uploads/')) return [imagePath];
          if (imagePath.includes(',')) {
            return imagePath.split(',')
              .map(img => img.trim())
              .filter(img => img)
              .map(img => {
                if (img.startsWith('http')) return img;
                if (img.startsWith('/uploads/')) return img;
                return `/uploads/events/${img}`;
              });
          }
          return [`/uploads/events/${imagePath}`];
        }
      }
      
      return [];
    };
    
    // Process events for display
    const events = rows.map(event => {
      // Parse gallery images with proper URLs
      const galleryImages = formatImageUrls(event.gallery_images);
      
      // Calculate event status dynamically if not set
      let eventStatus = event.status;
      if (!eventStatus) {
        const now = new Date();
        const startDate = new Date(event.start_date);
        const endDate = new Date(event.end_date);
        
        if (now < startDate) {
          eventStatus = 'Upcoming';
        } else if (now > endDate) {
          eventStatus = 'Past';
        } else {
          eventStatus = 'Ongoing';
        }
      }
      
      // Format date for display
      const formatDisplayDate = (startDate, endDate) => {
        if (!startDate) return 'Date not set';
        
        const start = new Date(startDate);
        const end = endDate ? new Date(endDate) : null;
        
        if (isNaN(start.getTime())) return 'Invalid date';
        
        if (!end || isNaN(end.getTime()) || startDate === endDate) {
          return start.toLocaleDateString('en-US', { 
            month: 'long', 
            day: 'numeric', 
            year: 'numeric' 
          });
        }
        
        if (start.getMonth() === end.getMonth() && start.getFullYear() === end.getFullYear()) {
          return `${start.toLocaleDateString('en-US', { month: 'long' })} ${start.getDate()}-${end.getDate()}, ${start.getFullYear()}`;
        }
        
        return `${start.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })} - ${end.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}`;
      };
      
      const displayDate = formatDisplayDate(event.start_date, event.end_date);
      
      // Use actual attendees count from the query
      const attendeesCount = event.attendees_count || 0;
      const maxAttendees = 100; // Default value
      const availableSeats = Math.max(0, maxAttendees - attendeesCount);
      const registrationOpen = eventStatus !== 'Past' && eventStatus !== 'Cancelled' && availableSeats > 0;
      
      return {
        id: event.id,
        title: event.title,
        start_date: event.start_date,
        end_date: event.end_date,
        display_date: displayDate,
        author_name: event.author_name,
        bookstore_location: event.bookstore_location,
        address: event.address,
        description: event.description,
        featured_books: event.featured_books,
        event_type: event.event_type,
        status: eventStatus,
        featured: event.featured === 1,
        gallery_images: galleryImages,
        attendees_count: attendeesCount,
        max_attendees: maxAttendees,
        available_seats: availableSeats,
        registration_open: registrationOpen,
        created_at: event.created_at,
        updated_at: event.updated_at
      };
    });
    
    // Count total events for pagination (need a separate query for count)
    let countQuery = `
      SELECT COUNT(*) as total 
      FROM events e
      WHERE 1=1
    `;
    
    const countParams = [];
    
    if (search) {
      countQuery += ' AND (e.title LIKE ? OR e.author_name LIKE ? OR e.bookstore_location LIKE ? OR e.description LIKE ?)';
      const searchParam = `%${search}%`;
      countParams.push(searchParam, searchParam, searchParam, searchParam);
    }
    
    if (eventType && eventType !== 'all') {
      countQuery += ' AND e.event_type = ?';
      countParams.push(eventType);
    }
    
    if (showPast === 'false') {
      const now = new Date().toISOString().split('T')[0];
      countQuery += ' AND (e.status IN ("Upcoming", "Ongoing") OR (e.status IS NULL AND e.start_date >= ?))';
      countParams.push(now);
    }
    
    const [countResult] = await pool.query(countQuery, countParams);
    const totalEvents = countResult[0]?.total || events.length;
    
    console.log(`✅ Found ${events.length} display events out of ${totalEvents} total`);
    console.log(`🖼️ Sample event images:`, events[0]?.gallery_images);
    
    res.json({ 
      success: true, 
      data: events,
      meta: {
        total: totalEvents,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(totalEvents / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('❌ Error fetching display events:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch events',
      details: error.message
    });
  }
});

// Configure multer for event gallery images upload
const eventStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/events';
    
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname).toLowerCase();
    // Store just the filename, not the full path
    cb(null, `event-${uniqueSuffix}${ext}`);
  }
});

const eventFileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|webp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (extname && mimetype) {
    return cb(null, true);
  } else {
    cb(new Error('Only image files are allowed (jpeg, jpg, png, gif, webp)'));
  }
};

const uploadEventImages = multer({ 
  storage: eventStorage, 
  fileFilter: eventFileFilter,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit per file
});

// GET all events with search and filters (ADMIN)
app.get('/api/events', requireAdmin, async (req, res) => {
  try {
    const { search, status, eventType } = req.query;
    let query = 'SELECT * FROM events';
    const params = [];
    
    // Add filters if provided
    const conditions = [];
    
    if (search) {
      conditions.push('(title LIKE ? OR author_name LIKE ? OR bookstore_location LIKE ? OR address LIKE ?)');
      params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
    }
    
    if (status && status !== 'all') {
      conditions.push('status = ?');
      params.push(status);
    }
    
    if (eventType && eventType !== 'all') {
      conditions.push('event_type = ?');
      params.push(eventType);
    }
    
    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    
    query += ' ORDER BY created_at DESC';
    
    const [rows] = await pool.query(query, params);
    
    // Helper function to format image URLs for admin
    const formatImageUrls = (imagePath) => {
      if (!imagePath) return [];
      
      if (typeof imagePath === 'string') {
        try {
          const parsed = JSON.parse(imagePath);
          if (Array.isArray(parsed)) {
            return parsed.map(img => `/uploads/events/${path.basename(img)}`);
          }
          return [`/uploads/events/${path.basename(parsed)}`];
        } catch (error) {
          if (imagePath.includes(',')) {
            return imagePath.split(',')
              .map(img => img.trim())
              .filter(img => img)
              .map(img => `/uploads/events/${path.basename(img)}`);
          }
          return [`/uploads/events/${path.basename(imagePath)}`];
        }
      }
      
      return [];
    };
    
    const events = rows.map(event => ({
      id: event.id,
      title: event.title,
      date: event.date,
      start_date: event.start_date,
      end_date: event.end_date,
      author_name: event.author_name,
      bookstore_location: event.bookstore_location,
      address: event.address,
      description: event.description,
      featured_books: event.featured_books,
      event_type: event.event_type,
      status: event.status,
      featured: event.featured === 1,
      gallery_images: formatImageUrls(event.gallery_images),
      created_at: event.created_at,
      updated_at: event.updated_at
    }));
    
    res.json({ 
      success: true, 
      data: events,
      count: events.length 
    });
  } catch (error) {
    console.error('❌ Error fetching events:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch events',
      details: error.message 
    });
  }
});

// POST create event with multiple images
app.post('/api/events', requireAdmin, uploadEventImages.array('galleryImages', 10), async (req, res) => {
  try {
    console.log('📝 Creating new event...');
    console.log('📁 Uploaded files:', req.files);
    
    const {
      title,
      startDate,
      endDate,
      authorName,
      bookstoreLocation,
      address,
      description,
      featuredBooks,
      eventType,
      status,
      featured
    } = req.body;

    // Validate required fields
    if (!title || !authorName || !bookstoreLocation || !address || !description || !startDate || !endDate) {
      console.log('❌ Validation failed - missing required fields');
      
      // Delete uploaded files if validation fails
      if (req.files && req.files.length > 0) {
        req.files.forEach(file => {
          fs.unlink(file.path, (err) => {
            if (err) console.error('❌ Error deleting uploaded file:', err);
          });
        });
      }
      
      return res.status(400).json({ 
        success: false, 
        error: 'All fields marked with * are required' 
      });
    }

    // Handle gallery images - store just filenames in database
    let galleryImages = [];
    if (req.files && req.files.length > 0) {
      galleryImages = req.files.map(file => file.filename); // Just store filename
      console.log('🖼️ Storing images:', galleryImages);
    }

    // Parse dates for MySQL
    const mysqlStartDate = parseDateForMySQL(startDate);
    const mysqlEndDate = parseDateForMySQL(endDate);

    console.log('📅 Date parsing:', {
      inputStartDate: startDate,
      mysqlStartDate,
      inputEndDate: endDate,
      mysqlEndDate
    });

    // Generate display date from start and end dates
    const generateDisplayDate = (start, end) => {
      if (!start) return '';
      
      const startDate = new Date(start);
      const endDate = end ? new Date(end) : null;
      
      if (isNaN(startDate.getTime())) return '';
      
      if (!end || isNaN(endDate.getTime()) || start === end) {
        return startDate.toLocaleDateString('en-US', { 
          month: 'long', 
          day: 'numeric', 
          year: 'numeric' 
        });
      }
      
      if (startDate.getMonth() === endDate.getMonth() && startDate.getFullYear() === endDate.getFullYear()) {
        return `${startDate.toLocaleDateString('en-US', { month: 'long' })} ${startDate.getDate()}-${endDate.getDate()}, ${startDate.getFullYear()}`;
      }
      
      return `${startDate.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })} - ${endDate.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}`;
    };

    const displayDate = generateDisplayDate(mysqlStartDate, mysqlEndDate);

    const [result] = await pool.query(
      `INSERT INTO events 
      (title, date, start_date, end_date, author_name, bookstore_location, 
       address, description, featured_books, event_type, status, featured, gallery_images) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        title,
        displayDate, // Generated display date
        mysqlStartDate,
        mysqlEndDate,
        authorName,
        bookstoreLocation,
        address,
        description,
        featuredBooks || '',
        eventType || 'Book Signing',
        status || 'Upcoming',
        featured === 'true' || featured === true ? 1 : 0,
        JSON.stringify(galleryImages) // Store as JSON array of filenames
      ]
    );

    const newEvent = {
      id: result.insertId,
      title,
      date: displayDate,
      start_date: mysqlStartDate,
      end_date: mysqlEndDate,
      author_name: authorName,
      bookstore_location: bookstoreLocation,
      address,
      description,
      featured_books: featuredBooks,
      event_type: eventType,
      status,
      featured: featured === 'true' || featured === true,
      gallery_images: galleryImages.map(img => `/uploads/events/${img}`) // Return full URLs for response
    };

    console.log('✅ Event created successfully:', newEvent.id);

    res.status(201).json({ 
      success: true, 
      data: newEvent,
      message: 'Event created successfully'
    });
  } catch (error) {
    console.error('❌ Error creating event:', error);
    
    // Delete uploaded files if error occurred
    if (req.files && req.files.length > 0) {
      req.files.forEach(file => {
        fs.unlink(file.path, (err) => {
          if (err) console.error('❌ Error deleting uploaded file:', err);
        });
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'Failed to create event',
      details: error.message 
    });
  }
});

// PUT update event
app.put('/api/events/:id', requireAdmin, uploadEventImages.array('galleryImages', 10), async (req, res) => {
  try {
    const { id } = req.params;
    console.log('📝 Updating event ID:', id);

    const {
      title,
      startDate,
      endDate,
      authorName,
      bookstoreLocation,
      address,
      description,
      featuredBooks,
      eventType,
      status,
      featured
    } = req.body;

    // Get existing event
    const [existingRows] = await pool.query('SELECT gallery_images FROM events WHERE id = ?', [id]);
    
    if (existingRows.length === 0) {
      console.log('❌ Event not found:', id);
      
      // Delete uploaded files if event doesn't exist
      if (req.files && req.files.length > 0) {
        req.files.forEach(file => {
          fs.unlink(file.path, (err) => {
            if (err) console.error('❌ Error deleting uploaded file:', err);
          });
        });
      }
      
      return res.status(404).json({ 
        success: false, 
        error: 'Event not found' 
      });
    }

    // Parse existing gallery images (they should be stored as filenames)
    let existingImages = [];
    try {
      const parsed = existingRows[0].gallery_images ? JSON.parse(existingRows[0].gallery_images) : [];
      existingImages = Array.isArray(parsed) ? parsed : [parsed];
    } catch (e) {
      console.error('❌ Error parsing existing gallery images:', e);
      // If it's a string with comma separation
      if (typeof existingRows[0].gallery_images === 'string') {
        existingImages = existingRows[0].gallery_images.split(',')
          .map(img => img.trim())
          .filter(img => img)
          .map(img => path.basename(img)); // Extract just filename
      }
    }

    // Handle new gallery images
    let newImages = [];
    if (req.files && req.files.length > 0) {
      newImages = req.files.map(file => file.filename); // Just store filenames
      console.log('🖼️ New images to add:', newImages);
    }

    // Combine existing and new images (both should be just filenames)
    const allImages = [...existingImages, ...newImages];
    
    // Parse dates for MySQL
    const mysqlStartDate = parseDateForMySQL(startDate);
    const mysqlEndDate = parseDateForMySQL(endDate);

    // Generate display date
    const generateDisplayDate = (start, end) => {
      if (!start) return '';
      
      const startDate = new Date(start);
      const endDate = end ? new Date(end) : null;
      
      if (isNaN(startDate.getTime())) return '';
      
      if (!end || isNaN(endDate.getTime()) || start === end) {
        return startDate.toLocaleDateString('en-US', { 
          month: 'long', 
          day: 'numeric', 
          year: 'numeric' 
        });
      }
      
      if (startDate.getMonth() === endDate.getMonth() && startDate.getFullYear() === endDate.getFullYear()) {
        return `${startDate.toLocaleDateString('en-US', { month: 'long' })} ${startDate.getDate()}-${endDate.getDate()}, ${startDate.getFullYear()}`;
      }
      
      return `${startDate.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })} - ${endDate.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}`;
    };

    const displayDate = generateDisplayDate(mysqlStartDate, mysqlEndDate);

    // Prepare update data
    const updateData = {
      title: title ? title.trim() : undefined,
      date: displayDate, // Generated display date
      start_date: mysqlStartDate,
      end_date: mysqlEndDate,
      author_name: authorName ? authorName.trim() : undefined,
      bookstore_location: bookstoreLocation ? bookstoreLocation.trim() : undefined,
      address: address ? address.trim() : undefined,
      description: description ? description.trim() : undefined,
      featured_books: featuredBooks ? featuredBooks.trim() : undefined,
      event_type: eventType || undefined,
      status: status || undefined,
      featured: featured !== undefined ? (featured === 'true' || featured === true ? 1 : 0) : undefined,
      gallery_images: JSON.stringify(allImages) // Store as JSON array of filenames
    };

    // Remove undefined values
    Object.keys(updateData).forEach(key => {
      if (updateData[key] === undefined) {
        delete updateData[key];
      }
    });

    console.log('💾 Update data:', updateData);

    // Build dynamic UPDATE query
    const fields = Object.keys(updateData);
    if (fields.length === 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'No data provided for update' 
      });
    }

    const setClause = fields.map(field => `${field} = ?`).join(', ');
    const values = fields.map(field => updateData[field]);
    values.push(id);

    const query = `UPDATE events SET ${setClause} WHERE id = ?`;
    
    const [result] = await pool.query(query, values);

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Event not found or no changes made' 
      });
    }

    // Get the updated event
    const [updatedRows] = await pool.query('SELECT * FROM events WHERE id = ?', [id]);
    const updatedEvent = updatedRows[0];

    // Format gallery images for response
    let responseGalleryImages = [];
    try {
      const parsed = updatedEvent.gallery_images ? JSON.parse(updatedEvent.gallery_images) : [];
      responseGalleryImages = Array.isArray(parsed) 
        ? parsed.map(img => `/uploads/events/${img}`)
        : [`/uploads/events/${parsed}`];
    } catch (e) {
      console.error('❌ Error parsing gallery images for response:', e);
    }

    const responseEvent = {
      id: updatedEvent.id,
      title: updatedEvent.title,
      date: updatedEvent.date,
      start_date: updatedEvent.start_date,
      end_date: updatedEvent.end_date,
      author_name: updatedEvent.author_name,
      bookstore_location: updatedEvent.bookstore_location,
      address: updatedEvent.address,
      description: updatedEvent.description,
      featured_books: updatedEvent.featured_books,
      event_type: updatedEvent.event_type,
      status: updatedEvent.status,
      featured: updatedEvent.featured === 1,
      gallery_images: responseGalleryImages,
      created_at: updatedEvent.created_at,
      updated_at: updatedEvent.updated_at
    };

    console.log('✅ Event updated successfully:', id);

    res.json({ 
      success: true, 
      data: responseEvent,
      message: 'Event updated successfully' 
    });
  } catch (error) {
    console.error('❌ Error updating event:', error);
    
    // Delete uploaded files if error occurred
    if (req.files && req.files.length > 0) {
      req.files.forEach(file => {
        fs.unlink(file.path, (err) => {
          if (err) console.error('❌ Error deleting uploaded file:', err);
        });
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'Failed to update event',
      details: error.message 
    });
  }
});


// POST register for an event (public)
app.post('/api/events/:id/register', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, phone, notes } = req.body;
    
    // Validate required fields
    if (!name || !email) {
      return res.status(400).json({ 
        success: false, 
        error: 'Name and email are required' 
      });
    }
    
    // Check if event exists and is upcoming
    const [eventRows] = await pool.query(
      `SELECT * FROM events WHERE id = ?`,
      [id]
    );
    
    if (eventRows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Event not found' 
      });
    }
    
    const event = eventRows[0];
    
    // Check if event is past
    const now = new Date();
    const eventDate = new Date(event.start_date);
    if (eventDate < now) {
      return res.status(400).json({ 
        success: false, 
        error: 'This event has already ended' 
      });
    }
    
    // Check if event status is not Upcoming/Ongoing
    if (event.status === 'Past' || event.status === 'Cancelled') {
      return res.status(400).json({ 
        success: false, 
        error: 'Registration is closed for this event' 
      });
    }
    
    // Check if user already registered
    const [existingRegs] = await pool.query(
      `SELECT id FROM event_registrations 
       WHERE event_id = ? AND email = ?`,
      [id, email]
    );
    
    if (existingRegs.length > 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'You are already registered for this event' 
      });
    }
    
    // Optional: Check event capacity
    const [registrationCountRows] = await pool.query(
      `SELECT COUNT(*) as count FROM event_registrations 
       WHERE event_id = ? AND status IN ('pending', 'confirmed')`,
      [id]
    );
    
    const registrationCount = registrationCountRows[0].count;
    
    // Assuming max capacity of 100 if not specified
    const maxCapacity = 100;
    if (registrationCount >= maxCapacity) {
      return res.status(400).json({ 
        success: false, 
        error: 'Event is at full capacity' 
      });
    }
    
    // Create registration
    const [result] = await pool.query(
      `INSERT INTO event_registrations 
       (event_id, name, email, phone, notes, status) 
       VALUES (?, ?, ?, ?, ?, 'pending')`,
      [id, name, email, phone || null, notes || null]
    );
    
    // Update event attendees count
    await pool.query(
      `UPDATE events 
       SET attendees_count = COALESCE(attendees_count, 0) + 1 
       WHERE id = ?`,
      [id]
    );
    
    // Get registration details
    const [newRegRows] = await pool.query(
      `SELECT * FROM event_registrations WHERE id = ?`,
      [result.insertId]
    );
    
    console.log(`✅ Registration created for event ${id}: ${email}`);
    
    res.json({ 
      success: true, 
      data: {
        id: newRegRows[0].id,
        event_id: newRegRows[0].event_id,
        name: newRegRows[0].name,
        email: newRegRows[0].email,
        status: newRegRows[0].status,
        registration_date: newRegRows[0].registration_date
      },
      message: 'Successfully registered for the event!'
    });
    
  } catch (error) {
    console.error('❌ Error creating registration:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to register for event',
      details: error.message 
    });
  }
});

// GET event registrations (ADMIN only)
app.get('/api/events/:id/registrations', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.query;
    
    let query = `
      SELECT * FROM event_registrations 
      WHERE event_id = ?
    `;
    
    const params = [id];
    
    if (status && status !== 'all') {
      query += ' AND status = ?';
      params.push(status);
    }
    
    query += ' ORDER BY registration_date DESC';
    
    const [rows] = await pool.query(query, params);
    
    res.json({ 
      success: true, 
      data: rows,
      count: rows.length 
    });
  } catch (error) {
    console.error('❌ Error fetching registrations:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch registrations',
      details: error.message 
    });
  }
});

// UPDATE registration status (ADMIN only)
app.put('/api/registrations/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    if (!status || !['pending', 'confirmed', 'cancelled'].includes(status)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Valid status is required' 
      });
    }
    
    const [result] = await pool.query(
      `UPDATE event_registrations 
       SET status = ? 
       WHERE id = ?`,
      [status, id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Registration not found' 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Registration status updated successfully' 
    });
  } catch (error) {
    console.error('❌ Error updating registration:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to update registration',
      details: error.message 
    });
  }
});

// GET event stats including registration count
app.get('/api/events-display/stats', async (req, res) => {
  try {
    const [totalEvents] = await pool.query(
      `SELECT COUNT(*) as count FROM events`
    );
    
    const [upcomingEvents] = await pool.query(
      `SELECT COUNT(*) as count FROM events 
       WHERE status IN ('Upcoming', 'Ongoing') 
       OR (status IS NULL AND start_date >= CURDATE())`
    );
    
    const [featuredEvents] = await pool.query(
      `SELECT COUNT(*) as count FROM events WHERE featured = 1`
    );
    
    const [totalAttendees] = await pool.query(
      `SELECT COUNT(*) as count FROM event_registrations 
       WHERE status IN ('pending', 'confirmed')`
    );
    
    res.json({ 
      success: true, 
      data: {
        total_events: totalEvents[0].count,
        upcoming_events: upcomingEvents[0].count,
        featured_events: featuredEvents[0].count,
        total_attendees: totalAttendees[0].count || 0
      }
    });
  } catch (error) {
    console.error('❌ Error fetching event stats:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch stats',
      details: error.message 
    });
  }
});


// ========== TRADITIONAL PUBLISHERS ROUTES ==========

// GET all traditional publishers
app.get('/api/trad-publishers', async (req, res) => {
  try {
    const [publishers] = await pool.query(`
      SELECT tp.*, 
             GROUP_CONCAT(pe.email SEPARATOR ', ') as emails
      FROM traditional_publishers tp
      LEFT JOIN publisher_emails pe ON tp.id = pe.publisher_id
      GROUP BY tp.id
      ORDER BY tp.created_at DESC
    `);
    
    // Parse emails from string to array
    const formattedPublishers = publishers.map(publisher => ({
      ...publisher,
      emails: publisher.emails ? publisher.emails.split(', ') : []
    }));
    
    res.json({ success: true, data: formattedPublishers });
  } catch (error) {
    console.error('Error fetching traditional publishers:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET single traditional publisher by ID
app.get('/api/trad-publishers/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get publisher basic info
    const [publisherRows] = await pool.query(
      'SELECT * FROM traditional_publishers WHERE id = ?',
      [id]
    );
    
    if (publisherRows.length === 0) {
      return res.status(404).json({ success: false, error: 'Publisher not found' });
    }
    
    // Get emails for this publisher
    const [emailRows] = await pool.query(
      'SELECT email FROM publisher_emails WHERE publisher_id = ?',
      [id]
    );
    
    const publisher = {
      ...publisherRows[0],
      emails: emailRows.map(row => row.email)
    };
    
    res.json({ success: true, data: publisher });
  } catch (error) {
    console.error('Error fetching traditional publisher:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST create new traditional publisher
app.post('/api/trad-publishers', requireAdmin, async (req, res) => {
  let connection;
  try {
    const { company_name, genre, website, guidelines, emails = [] } = req.body;
    
    // Validate required fields
    if (!company_name) {
      return res.status(400).json({ 
        success: false, 
        error: 'Company name is required' 
      });
    }
    
    connection = await pool.getConnection();
    await connection.beginTransaction();
    
    // Insert publisher
    const [publisherResult] = await connection.query(
      `INSERT INTO traditional_publishers (company_name, genre, website, guidelines) 
       VALUES (?, ?, ?, ?)`,
      [company_name, genre || null, website || null, guidelines || null]
    );
    
    const publisherId = publisherResult.insertId;
    
    // Insert emails if provided
    if (Array.isArray(emails) && emails.length > 0) {
      const emailValues = emails
        .filter(email => email && email.trim())
        .map(email => [publisherId, email.trim()]);
      
      if (emailValues.length > 0) {
        await connection.query(
          'INSERT INTO publisher_emails (publisher_id, email) VALUES ?',
          [emailValues]
        );
      }
    }
    
    await connection.commit();
    
    // Get the complete publisher data
    const [newPublisher] = await pool.query(
      'SELECT * FROM traditional_publishers WHERE id = ?',
      [publisherId]
    );
    
    const [publisherEmails] = await pool.query(
      'SELECT email FROM publisher_emails WHERE publisher_id = ?',
      [publisherId]
    );
    
    const completePublisher = {
      ...newPublisher[0],
      emails: publisherEmails.map(row => row.email)
    };
    
    res.status(201).json({ 
      success: true, 
      data: completePublisher,
      message: 'Traditional publisher created successfully'
    });
  } catch (error) {
    if (connection) {
      await connection.rollback();
    }
    console.error('Error creating traditional publisher:', error);
    res.status(500).json({ success: false, error: error.message });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

// PUT update traditional publisher
app.put('/api/trad-publishers/:id', requireAdmin, async (req, res) => {
  let connection;
  try {
    const { id } = req.params;
    const { company_name, genre, website, guidelines, emails = [], status } = req.body;
    
    // Check if publisher exists
    const [existingRows] = await pool.query(
      'SELECT id FROM traditional_publishers WHERE id = ?',
      [id]
    );
    
    if (existingRows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Publisher not found' 
      });
    }
    
    connection = await pool.getConnection();
    await connection.beginTransaction();
    
    // Update publisher
    await connection.query(
      `UPDATE traditional_publishers 
       SET company_name = ?, genre = ?, website = ?, guidelines = ?, status = ?
       WHERE id = ?`,
      [company_name, genre || null, website || null, guidelines || null, status || 'active', id]
    );
    
    // Delete existing emails
    await connection.query(
      'DELETE FROM publisher_emails WHERE publisher_id = ?',
      [id]
    );
    
    // Insert new emails if provided
    if (Array.isArray(emails) && emails.length > 0) {
      const emailValues = emails
        .filter(email => email && email.trim())
        .map(email => [id, email.trim()]);
      
      if (emailValues.length > 0) {
        await connection.query(
          'INSERT INTO publisher_emails (publisher_id, email) VALUES ?',
          [emailValues]
        );
      }
    }
    
    await connection.commit();
    
    // Get updated publisher data
    const [updatedPublisher] = await pool.query(
      'SELECT * FROM traditional_publishers WHERE id = ?',
      [id]
    );
    
    const [publisherEmails] = await pool.query(
      'SELECT email FROM publisher_emails WHERE publisher_id = ?',
      [id]
    );
    
    const completePublisher = {
      ...updatedPublisher[0],
      emails: publisherEmails.map(row => row.email)
    };
    
    res.json({ 
      success: true, 
      data: completePublisher,
      message: 'Traditional publisher updated successfully'
    });
  } catch (error) {
    if (connection) {
      await connection.rollback();
    }
    console.error('Error updating traditional publisher:', error);
    res.status(500).json({ success: false, error: error.message });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});

// DELETE traditional publisher
app.delete('/api/trad-publishers/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    console.log('Delete request for ID:', id); // Add logging
    
    // Check if publisher exists
    const [existingRows] = await pool.query(
      'SELECT id FROM traditional_publishers WHERE id = ?',
      [id]
    );
    
    console.log('Existing rows:', existingRows); // Add logging
    
    if (existingRows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Publisher not found' 
      });
    }
    
    await pool.query('DELETE FROM traditional_publishers WHERE id = ?', [id]);
    
    console.log('Publisher deleted successfully'); // Add logging
    
    res.json({ 
      success: true, 
      message: 'Traditional publisher deleted successfully' 
    });
  } catch (error) {
    console.error('Error deleting traditional publisher:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Search traditional publishers
app.get('/api/trad-publishers/search/:query', async (req, res) => {
  try {
    const { query } = req.params;
    const searchQuery = `%${query}%`;
    
    const [publishers] = await pool.query(`
      SELECT tp.*, 
             GROUP_CONCAT(pe.email SEPARATOR ', ') as emails
      FROM traditional_publishers tp
      LEFT JOIN publisher_emails pe ON tp.id = pe.publisher_id
      WHERE tp.company_name LIKE ? 
         OR tp.genre LIKE ?
      GROUP BY tp.id
      ORDER BY tp.created_at DESC
    `, [searchQuery, searchQuery]);
    
    // Parse emails from string to array
    const formattedPublishers = publishers.map(publisher => ({
      ...publisher,
      emails: publisher.emails ? publisher.emails.split(', ') : []
    }));
    
    res.json({ success: true, data: formattedPublishers });
  } catch (error) {
    console.error('Error searching traditional publishers:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Health check endpoint from routes
app.get('/api/health-check', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ 
      success: true, 
      message: 'API is running',
      database: 'connected',
      mode: isDevelopment ? 'Development' : 'Production'
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'API is running',
      database: 'disconnected',
      mode: isDevelopment ? 'Development' : 'Production',
      error: error.message 
    });
  }
});

/*
|--------------------------------------------------------------------------
| ROOT ENDPOINT
|--------------------------------------------------------------------------
*/
app.get('/', (req, res) => {
  res.json({
    message: 'Fulfill1st Development Backend API',
    domain: 'Local Development',
    status: 'running',
    mode: isDevelopment ? 'Development' : 'Production',
    frontend: 'http://192.168.68.4:5177',
    endpoints: {
      health: '/api/health',
      test: '/api/test',
      'dev-session': '/api/dev/session',
      'dev-env': '/api/dev/env',
      bookstores: '/api/bookstores',
      authors: '/api/authors',
      books: '/api/books',
      'social-media-links': '/api/social-media-links',
      login: '/api/login',
      'admin-dashboard': '/api/admin/dashboard'
    }
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
    backend: 'Local Development',
    mode: isDevelopment ? 'Development' : 'Production',
    suggestion: 'Try /api/health or /api/test'
  });
});

/*
|--------------------------------------------------------------------------
| ERROR HANDLER
|--------------------------------------------------------------------------
*/
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err);
  
  if (isDevelopment) {
    res.status(500).json({
      error: 'Internal server error',
      message: err.message,
      stack: err.stack
    });
  } else {
    res.status(500).json({
      error: 'Internal server error',
      message: 'Something went wrong'
    });
  }
});

/*
|--------------------------------------------------------------------------
| START SERVER
|--------------------------------------------------------------------------
*/
app.listen(PORT, () => {
  console.log(`
===========================================
🚀 DEVELOPMENT SERVER RUNNING
===========================================
Mode: ${isDevelopment ? 'Development' : 'Production'}
URL: http://localhost:${PORT}
API Base: http://localhost:${PORT}/api
Frontend: http://192.168.68.4:5177
Database: Connected
===========================================
📝 Development Features:
- Detailed request logging
- Session debugging endpoints
- Permissive CORS for LAN
- Development-specific routes
===========================================
`);
});