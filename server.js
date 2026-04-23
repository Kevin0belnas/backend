const express = require('express');
const cors = require('cors');
const session = require('express-session');
const { pool, testConnection, ensureConnection, parseDateForMySQL } = require('./db');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production-2024';

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
      'http://192.168.68.51:5177', // Your LAN IP for development
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

// CORS first
app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));

// THEN increase payload limits (only ONCE)
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

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
    frontend: 'http://192.168.68.78:5177'
  });
});

app.get('/api/test', (req, res) => {
  res.json({
    success: true,
    message: 'Backend is working!',
    mode: isDevelopment ? 'Development' : 'Production',
    allowedOrigins: [
      'http://192.168.68.78:5177',
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


// ========== BOOKSTORE ROUTES WITH BASE64 ==========

// Helper function to validate and optimize Base64 images for bookstores
const validateBookstoreImage = (base64String) => {
  if (!base64String) return null;
  
  // Check if it's a valid Base64 image
  if (!base64String.startsWith('data:image/')) {
    return null;
  }
  
  // Check size (max 2MB for bookstore images)
  const sizeInBytes = Buffer.from(base64String.split(',')[1] || '', 'base64').length;
  const sizeInMB = sizeInBytes / (1024 * 1024);
  
  if (sizeInMB > 2) {
    return null;
  }
  
  return base64String;
};

// GET all bookstores (with Base64 images)
app.get('/api/bookstores', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM bookstores ORDER BY created_at DESC');
    
    // Parse Base64 images using the same pattern as authors
    const parsedRows = rows.map(row => {
      let imageUrl = null;
      
      if (row.image_url) {
        // Check if it's a JSON string array
        if (typeof row.image_url === 'string' && row.image_url.startsWith('[')) {
          try {
            const parsed = JSON.parse(row.image_url);
            if (Array.isArray(parsed) && parsed.length > 0 && parsed[0].startsWith('data:image')) {
              imageUrl = parsed[0];
            } else if (Array.isArray(parsed) && parsed.length > 0) {
              imageUrl = parsed[0];
            }
          } catch (e) {
            imageUrl = row.image_url;
          }
        } 
        // Check if it's already a Base64 string
        else if (typeof row.image_url === 'string' && row.image_url.startsWith('data:image')) {
          imageUrl = row.image_url;
        }
        // Check if it's a JSON object
        else if (typeof row.image_url === 'string' && row.image_url.startsWith('{')) {
          try {
            const parsed = JSON.parse(row.image_url);
            imageUrl = Array.isArray(parsed) ? parsed[0] : parsed;
          } catch (e) {
            imageUrl = row.image_url;
          }
        }
        else {
          imageUrl = row.image_url;
        }
      }
      
      return {
        ...row,
        image_url: imageUrl
      };
    });
    
    res.json({ success: true, data: parsedRows });
  } catch (error) {
    console.error('Error fetching bookstores:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET single bookstore by ID (with Base64)
app.get('/api/bookstores/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const [bookstoreRows] = await pool.query('SELECT * FROM bookstores WHERE id = ?', [id]);
    
    if (bookstoreRows.length === 0) {
      return res.status(404).json({ success: false, error: 'Bookstore not found' });
    }
    
    const bookstore = bookstoreRows[0];
    
    // Parse image - handle array format
    let imageUrl = null;
    if (bookstore.image_url) {
      if (typeof bookstore.image_url === 'string' && bookstore.image_url.startsWith('[')) {
        try {
          const parsed = JSON.parse(bookstore.image_url);
          if (Array.isArray(parsed) && parsed.length > 0 && parsed[0].startsWith('data:image')) {
            imageUrl = parsed[0];
          } else if (Array.isArray(parsed) && parsed.length > 0) {
            imageUrl = parsed[0];
          }
        } catch (e) {
          imageUrl = bookstore.image_url;
        }
      } 
      else if (typeof bookstore.image_url === 'string' && bookstore.image_url.startsWith('data:image')) {
        imageUrl = bookstore.image_url;
      }
      else if (typeof bookstore.image_url === 'string' && bookstore.image_url.startsWith('{')) {
        try {
          const parsed = JSON.parse(bookstore.image_url);
          imageUrl = Array.isArray(parsed) ? parsed[0] : parsed;
        } catch (e) {
          imageUrl = bookstore.image_url;
        }
      }
      else {
        imageUrl = bookstore.image_url;
      }
    }
    
    // Get authors for this bookstore and parse their avatars
    const [authorRows] = await pool.query('SELECT * FROM authors WHERE bookstore_id = ?', [id]);
    const parsedAuthors = authorRows.map(author => ({
      ...author,
      avatar: parseAvatar(author.avatar)
    }));
    
    // Get books for this bookstore and parse their images
    const [bookRows] = await pool.query(`
      SELECT b.*, a.name as author_name 
      FROM books b 
      JOIN authors a ON b.author_id = a.id 
      WHERE b.bookstore_id = ?
    `, [id]);
    
    const parsedBooks = bookRows.map(book => ({
      ...book,
      image_url: parseBookImage(book.image_url)
    }));
    
    res.json({
      success: true,
      data: {
        ...bookstore,
        image_url: imageUrl,
        authors: parsedAuthors,
        books: parsedBooks
      }
    });
  } catch (error) {
    console.error('Error fetching bookstore:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST create bookstore (with Base64 image)
app.post('/api/bookstores', requireAdmin, async (req, res) => {
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
      reviews = 0,
      image // Base64 string
    } = req.body;

    if (isDevelopment) {
      console.log('Bookstore POST request:', { name, location, category });
      console.log('Has image:', !!image);
    }

    // Validate required fields
    if (!name || !location) {
      return res.status(400).json({ 
        success: false, 
        error: 'Name and location are required' 
      });
    }

    // Clean and validate fields
    const cleanEstablished = established === '' ? null : parseInt(established);
    const cleanRating = rating === '' ? 0 : parseFloat(rating);
    const cleanReviews = reviews === '' ? 0 : parseInt(reviews);
    const cleanPhone = phone ? phone.trim() : '';
    
    // Validate and optimize image
    let imageToStore = null;
    if (image) {
      const validatedImage = validateBookstoreImage(image);
      if (!validatedImage) {
        return res.status(400).json({ 
          success: false, 
          error: 'Invalid or oversized image. Maximum size is 2MB.' 
        });
      }
      imageToStore = JSON.stringify([validatedImage]);
    }

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
        imageToStore
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
      image_url: imageToStore ? JSON.parse(imageToStore)[0] : null
    };

    res.status(201).json({ 
      success: true, 
      data: newBookstore,
      message: 'Bookstore created successfully'
    });
  } catch (error) {
    console.error('Error creating bookstore:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// PUT update bookstore (with Base64 image)
app.put('/api/bookstores/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const {
      name,
      location,
      address,
      established,
      description,
      email,
      phone,
      website,
      logo,
      category,
      rating,
      reviews,
      image // Base64 string
    } = req.body;

    if (isDevelopment) {
      console.log('Bookstore PUT request:', { id, name, category });
      console.log('Has image:', !!image);
    }

    // Check if bookstore exists
    const [existingRows] = await pool.query('SELECT id, image_url FROM bookstores WHERE id = ?', [id]);
    
    if (existingRows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Bookstore not found' 
      });
    }

    // Clean fields
    const cleanEstablished = established === '' ? null : parseInt(established);
    const cleanRating = rating === '' ? 0 : parseFloat(rating);
    const cleanReviews = reviews === '' ? 0 : parseInt(reviews);
    const cleanPhone = phone ? phone.trim() : '';

    // Handle image update
    let imageToStore = existingRows[0].image_url;
    
    if (image) {
      const validatedImage = validateBookstoreImage(image);
      if (!validatedImage) {
        return res.status(400).json({ 
          success: false, 
          error: 'Invalid or oversized image. Maximum size is 2MB.' 
        });
      }
      imageToStore = JSON.stringify([validatedImage]);
    }

    await pool.query(
      `UPDATE bookstores SET 
        name = ?,
        location = ?,
        address = ?,
        established = ?,
        description = ?,
        email = ?,
        phone = ?,
        website = ?,
        logo = ?,
        category = ?,
        rating = ?,
        reviews = ?,
        image_url = ?
      WHERE id = ?`,
      [
        name,
        location,
        address || null,
        cleanEstablished,
        description || null,
        email || null,
        cleanPhone,
        website || null,
        logo || '📚',
        category || 'Independent',
        cleanRating,
        cleanReviews,
        imageToStore,
        id
      ]
    );
    
    res.json({ success: true, message: 'Bookstore updated successfully' });
  } catch (error) {
    console.error('Error updating bookstore:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// DELETE bookstore
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


// ========== AUTHOR ROUTES WITH BASE64 ==========

// Helper function to validate and optimize Base64 images for authors
const validateAuthorImage = (base64String) => {
  if (!base64String) return null;
  
  // Check if it's a valid Base64 image
  if (!base64String.startsWith('data:image/')) {
    return null;
  }
  
  // Check size (max 500KB for author avatars)
  const sizeInBytes = Buffer.from(base64String.split(',')[1] || '', 'base64').length;
  const sizeInMB = sizeInBytes / (1024 * 1024);
  
  if (sizeInMB > 0.5) {
    return null;
  }
  
  return base64String;
};

// Helper function to parse avatar from database
const parseAvatar = (avatarData) => {
  if (!avatarData) return '👤';
  
  // If it's a JSON string array (our storage format)
  if (typeof avatarData === 'string' && avatarData.startsWith('[')) {
    try {
      const parsed = JSON.parse(avatarData);
      if (Array.isArray(parsed) && parsed.length > 0 && parsed[0].startsWith('data:image')) {
        return parsed[0];  // Return just the Base64 string, not the array
      }
      return parsed;
    } catch (e) {
      // Not valid JSON, return as is
      return avatarData;
    }
  }
  
  // If it's already a Base64 string
  if (typeof avatarData === 'string' && avatarData.startsWith('data:image')) {
    return avatarData;
  }
  
  // If it's a JSON object string (old format)
  if (typeof avatarData === 'string' && avatarData.startsWith('{')) {
    try {
      const parsed = JSON.parse(avatarData);
      if (Array.isArray(parsed) && parsed.length > 0 && parsed[0].startsWith('data:image')) {
        return parsed[0];
      }
      return parsed;
    } catch (e) {
      return avatarData;
    }
  }
  
  // If it's an array (unlikely but possible)
  if (Array.isArray(avatarData) && avatarData.length > 0 && avatarData[0].startsWith('data:image')) {
    return avatarData[0];
  }
  
  // Default - return as is (should be emoji)
  return avatarData;
};

// GET all authors (for admin panel) - with Base64 images
app.get('/api/authors', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT a.*, b.name as bookstore_name 
      FROM authors a 
      LEFT JOIN bookstores b ON a.bookstore_id = b.id 
      ORDER BY a.created_at DESC
    `);
    
    // Parse Base64 avatars using the helper function
    const parsedRows = rows.map(row => ({
      ...row,
      avatar: parseAvatar(row.avatar)
    }));
    
    res.json({ success: true, data: parsedRows });
  } catch (error) {
    console.error('Error fetching all authors:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET author by ID - with Base64
app.get('/api/authors/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const [authorRows] = await pool.query('SELECT * FROM authors WHERE id = ?', [id]);
    
    if (authorRows.length === 0) {
      return res.status(404).json({ success: false, error: 'Author not found' });
    }
    
    const author = authorRows[0];
    
    // Parse avatar using helper
    const avatar = parseAvatar(author.avatar);
    
    // Get books for this author
    const [bookRows] = await pool.query(`
      SELECT b.*, a.name as author_name 
      FROM books b 
      JOIN authors a ON b.author_id = a.id 
      WHERE b.author_id = ?
    `, [id]);
    
    // Process book images if they exist
    const processedBooks = bookRows.map(book => {
      let bookImage = book.image_url;
      try {
        if (book.image_url && book.image_url.startsWith('data:image')) {
          bookImage = book.image_url;
        } else if (book.image_url && book.image_url.startsWith('{')) {
          const parsed = JSON.parse(book.image_url);
          bookImage = Array.isArray(parsed) ? parsed[0] : parsed;
        }
      } catch (e) {
        bookImage = book.image_url;
      }
      
      return {
        ...book,
        image_url: bookImage
      };
    });
    
    res.json({
      success: true,
      data: {
        ...author,
        avatar: avatar,
        books: processedBooks
      }
    });
  } catch (error) {
    console.error('Error fetching author:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET author's books (for the modal in frontend) - with Base64
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
    
    // Process book images using parseBookImage
    const processedBooks = bookRows.map(book => ({
      ...book,
      image_url: parseBookImage(book.image_url)
    }));
    
    res.json({
      success: true,
      data: {
        author: author,
        books: processedBooks
      }
    });
  } catch (error) {
    console.error('Error fetching author books:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// PUT update author - with Base64 avatar
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
    
    // Validate and optimize avatar if it's an image
    let avatarToStore = avatar;
    if (avatar && avatar.startsWith('data:image')) {
      const validatedAvatar = validateAuthorImage(avatar);
      if (!validatedAvatar) {
        return res.status(400).json({ 
          success: false, 
          error: 'Invalid or oversized avatar image. Maximum size is 500KB.' 
        });
      }
      // Store as JSON string array
      avatarToStore = JSON.stringify([validatedAvatar]);
    } else if (avatar && !avatar.startsWith('data:image')) {
      // For emojis, store as plain string
      avatarToStore = avatar;
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
      [bookstore_id, name, genre, bio, avatarToStore, books_count, id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Author not found' 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Author updated successfully',
      data: {
        id: parseInt(id),
        bookstore_id,
        name,
        genre,
        bio,
        avatar: avatar, // Return the original for response
        books_count
      }
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

// GET authors by bookstore - with Base64
app.get('/api/authors/bookstore/:bookstoreId', async (req, res) => {
  try {
    const { bookstoreId } = req.params;
    const [rows] = await pool.query('SELECT * FROM authors WHERE bookstore_id = ?', [bookstoreId]);
    
    // Parse avatars using helper
    const parsedRows = rows.map(row => ({
      ...row,
      avatar: parseAvatar(row.avatar)
    }));
    
    res.json({ success: true, data: parsedRows });
  } catch (error) {
    console.error('Error fetching authors:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST create author - with Base64 avatar
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
    
    // Validate and optimize avatar if it's an image
    let avatarToStore = avatar;
    if (avatar && avatar.startsWith('data:image')) {
      const validatedAvatar = validateAuthorImage(avatar);
      if (!validatedAvatar) {
        return res.status(400).json({ 
          success: false, 
          error: 'Invalid or oversized avatar image. Maximum size is 500KB.' 
        });
      }
      // Store as JSON string array
      avatarToStore = JSON.stringify([validatedAvatar]);
    }
    
    const [result] = await pool.query(
      `INSERT INTO authors (bookstore_id, name, genre, bio, avatar, books_count) 
      VALUES (?, ?, ?, ?, ?, ?)`,
      [bookstore_id, name, genre, bio, avatarToStore, books_count]
    );
    
    const newAuthor = {
      id: result.insertId,
      bookstore_id,
      name,
      genre,
      bio,
      avatar: avatar, // Return the original for preview
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


// ========== BOOK ROUTES WITH BASE64 ==========

// Helper function to validate and optimize Base64 images for books
const validateBookImage = (base64String) => {
  if (!base64String) return null;
  
  // Check if it's a valid Base64 image
  if (!base64String.startsWith('data:image/')) {
    return null;
  }
  
  // Check size (max 2MB for book covers)
  const sizeInBytes = Buffer.from(base64String.split(',')[1] || '', 'base64').length;
  const sizeInMB = sizeInBytes / (1024 * 1024);
  
  if (sizeInMB > 2) {
    return null;
  }
  
  return base64String;
};

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
    
    // Parse Base64 images
    const parsedRows = rows.map(row => ({
      ...row,
      image_url: parseBookImage(row.image_url)
    }));
    
    res.json({ success: true, data: parsedRows });
  } catch (error) {
    console.error('Error fetching all books:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Helper function to parse book image from database
const parseBookImage = (imageData) => {
  if (!imageData) return null;
  
  // If it's already a Base64 string
  if (typeof imageData === 'string' && imageData.startsWith('data:image')) {
    return imageData;
  }
  
  // If it's a JSON string array (our storage format) - CHECK FOR ARRAY FIRST
  if (typeof imageData === 'string' && imageData.startsWith('[')) {
    try {
      const parsed = JSON.parse(imageData);
      if (Array.isArray(parsed) && parsed.length > 0) {
        const firstImage = parsed[0];
        if (firstImage && firstImage.startsWith('data:image')) {
          return firstImage;
        }
        return firstImage;
      }
    } catch (e) {
      console.error('Error parsing array image data:', e);
      return imageData;
    }
  }
  
  // If it's a JSON object string (old format)
  if (typeof imageData === 'string' && imageData.startsWith('{')) {
    try {
      const parsed = JSON.parse(imageData);
      if (Array.isArray(parsed) && parsed.length > 0 && parsed[0].startsWith('data:image')) {
        return parsed[0];
      }
      return parsed;
    } catch (e) {
      return imageData;
    }
  }
  
  // If it's an array
  if (Array.isArray(imageData) && imageData.length > 0 && imageData[0].startsWith('data:image')) {
    return imageData[0];
  }
  
  return imageData;
};

// GET book by ID
app.get('/api/books/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    const [rows] = await pool.query(`
      SELECT b.*, a.name as author_name, bs.name as bookstore_name 
      FROM books b 
      JOIN authors a ON b.author_id = a.id 
      JOIN bookstores bs ON b.bookstore_id = bs.id 
      WHERE b.id = ?
    `, [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Book not found' });
    }
    
    const book = rows[0];
    book.image_url = parseBookImage(book.image_url);
    
    res.json({ success: true, data: book });
  } catch (error) {
    console.error('Error fetching book:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST create book - with Base64 image
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
      description = '',
      image_url = null
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
    
    // Check if author exists and belongs to bookstore
    const [authorRows] = await pool.query(
      'SELECT id FROM authors WHERE id = ? AND bookstore_id = ?', 
      [author_id, bookstore_id]
    );
    if (authorRows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Author not found or does not belong to the selected bookstore' 
      });
    }
    
    // Validate and optimize image if provided
    let imageToStore = null;
    if (image_url && image_url.startsWith('data:image')) {
      const validatedImage = validateBookImage(image_url);
      if (!validatedImage) {
        return res.status(400).json({ 
          success: false, 
          error: 'Invalid or oversized book cover image. Maximum size is 2MB.' 
        });
      }
      // Store as JSON string array
      imageToStore = JSON.stringify([validatedImage]);
    }
    
    const [result] = await pool.query(
      `INSERT INTO books (bookstore_id, author_id, title, price, genre, published_date, isbn, description, image_url) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [bookstore_id, author_id, title, price, genre, published_date, isbn, description, imageToStore]
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
      description,
      image_url: image_url // Return the original for preview
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

// PUT update book - with Base64 image
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
    
    // Validate and optimize image if it's a new Base64 image
    let imageToStore = image_url;
    if (image_url && image_url.startsWith('data:image')) {
      const validatedImage = validateBookImage(image_url);
      if (!validatedImage) {
        return res.status(400).json({ 
          success: false, 
          error: 'Invalid or oversized book cover image. Maximum size is 2MB.' 
        });
      }
      imageToStore = JSON.stringify([validatedImage]);
    } else if (image_url && !image_url.startsWith('data:image')) {
      // Keep existing image URL/path as is
      imageToStore = image_url;
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
      [bookstore_id, author_id, title, price, genre, published_date, isbn, description, imageToStore, id]
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
    
    const parsedRows = rows.map(row => ({
      ...row,
      image_url: parseBookImage(row.image_url)
    }));
    
    res.json({ success: true, data: parsedRows });
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
    
    const parsedRows = rows.map(row => ({
      ...row,
      image_url: parseBookImage(row.image_url)
    }));
    
    res.json({ success: true, data: parsedRows });
  } catch (error) {
    console.error('Error fetching books by author:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});


// ========== SOCIAL MEDIA LINKS ROUTES WITH BASE64 & MULTIPLE LINKS SUPPORT ==========

// Helper function to validate and optimize Base64 images for social media
const validateSocialMediaImage = (base64String) => {
  if (!base64String) return null;
  
  // Check if it's a valid Base64 image
  if (!base64String.startsWith('data:image/')) {
    return null;
  }
  
  // Check size (max 1MB for author images)
  const sizeInBytes = Buffer.from(base64String.split(',')[1] || '', 'base64').length;
  const sizeInMB = sizeInBytes / (1024 * 1024);
  
  if (sizeInMB > 1) {
    return null;
  }
  
  return base64String;
};

// GET all social media links (with Base64 images) - GROUPED BY AUTHOR
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
        custom_label as customLabel,
        display_order as displayOrder,
        is_active as isActive,
        created_at as createdAt,
        updated_at as updatedAt
      FROM social_media_links 
      ORDER BY author_name, display_order ASC, platform, created_at DESC
    `);
    
    // Group links by author
    const authorsMap = new Map();
    
    rows.forEach(row => {
      let authorImage = null;
      try {
        if (row.authorImage) {
          const parsed = JSON.parse(row.authorImage);
          authorImage = Array.isArray(parsed) ? parsed[0] : parsed;
        }
      } catch (e) {
        authorImage = row.authorImage;
      }
      
      const authorKey = row.authorName;
      
      if (!authorsMap.has(authorKey)) {
        authorsMap.set(authorKey, {
          id: row.id,
          authorName: row.authorName,
          authorEmail: row.authorEmail,
          authorImage: authorImage,
          isActive: row.isActive,
          links: [],
          createdAt: row.createdAt,
          updatedAt: row.updatedAt
        });
      }
      
      const author = authorsMap.get(authorKey);
      author.links.push({
        id: row.id,
        platform: row.platform,
        username: row.username,
        url: row.url,
        description: row.description,
        customLabel: row.customLabel,
        displayOrder: row.displayOrder,
        isActive: row.isActive,
        createdAt: row.createdAt,
        updatedAt: row.updatedAt
      });
      
      // Sort links by display order
      author.links.sort((a, b) => (a.displayOrder || 0) - (b.displayOrder || 0));
    });
    
    const result = Array.from(authorsMap.values());
    
    res.json({ 
      success: true, 
      data: result,
      total: result.length 
    });
  } catch (error) {
    console.error('Error fetching social media links:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET single author's social media links by name
app.get('/api/social-media-links/author/:authorName', async (req, res) => {
  try {
    const { authorName } = req.params;
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
        custom_label as customLabel,
        display_order as displayOrder,
        is_active as isActive,
        created_at as createdAt,
        updated_at as updatedAt
      FROM social_media_links 
      WHERE author_name = ?
      ORDER BY display_order ASC, platform, created_at DESC
    `, [decodeURIComponent(authorName)]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Author not found' });
    }
    
    let authorImage = null;
    try {
      if (rows[0].authorImage) {
        const parsed = JSON.parse(rows[0].authorImage);
        authorImage = Array.isArray(parsed) ? parsed[0] : parsed;
      }
    } catch (e) {
      authorImage = rows[0].authorImage;
    }
    
    const author = {
      authorName: rows[0].authorName,
      authorEmail: rows[0].authorEmail,
      authorImage: authorImage,
      isActive: rows[0].isActive,
      links: rows.map(row => ({
        id: row.id,
        platform: row.platform,
        username: row.username,
        url: row.url,
        description: row.description,
        customLabel: row.customLabel,
        displayOrder: row.displayOrder,
        isActive: row.isActive,
        createdAt: row.createdAt,
        updatedAt: row.updatedAt
      }))
    };
    
    res.json({ success: true, data: author });
  } catch (error) {
    console.error('Error fetching author links:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST create new social media link (supports multiple per author)
app.post('/api/social-media-links', async (req, res) => {
  try {
    const {
      authorName,
      authorEmail,
      platform,
      username,
      url,
      description,
      customLabel,
      displayOrder,
      isActive,
      authorImage // Base64 string
    } = req.body;

    if (isDevelopment) {
      console.log('Social media POST request:', { authorName, platform, username, url });
    }

    // Validate required fields
    if (!authorName || !url || !platform) {
      return res.status(400).json({ error: 'Author name, URL, and platform are required' });
    }

    // Validate URL format
    try {
      new URL(url);
    } catch (err) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    // Validate and optimize image (only for first link of author)
    let validatedImage = null;
    if (authorImage) {
      validatedImage = validateSocialMediaImage(authorImage);
      if (!validatedImage) {
        return res.status(400).json({ error: 'Invalid or oversized image. Maximum size is 1MB.' });
      }
    } else {
      // Check if author already has an image
      const [existingAuthor] = await pool.query(
        'SELECT author_image FROM social_media_links WHERE author_name = ? AND author_image IS NOT NULL LIMIT 1',
        [authorName]
      );
      if (existingAuthor.length > 0) {
        validatedImage = existingAuthor[0].author_image;
      }
    }

    // Store image as JSON
    const imageToStore = validatedImage ? JSON.stringify([validatedImage]) : null;

    const [result] = await pool.query(
      `INSERT INTO social_media_links 
        (author_name, author_email, author_image, platform, username, url, description, 
         custom_label, display_order, is_active) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        authorName,
        authorEmail || null,
        imageToStore,
        platform,
        username || null,
        url,
        description || null,
        customLabel || null,
        displayOrder || 0,
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
        custom_label as customLabel,
        display_order as displayOrder,
        is_active as isActive,
        created_at as createdAt,
        updated_at as updatedAt
      FROM social_media_links 
      WHERE id = ?
    `, [result.insertId]);

    const link = newLink[0];
    let parsedImage = null;
    try {
      if (link.authorImage) {
        const parsed = JSON.parse(link.authorImage);
        parsedImage = Array.isArray(parsed) ? parsed[0] : parsed;
      }
    } catch (e) {
      parsedImage = link.authorImage;
    }
    link.authorImage = parsedImage;

    res.status(201).json({ success: true, data: link });
  } catch (error) {
    console.error('Error creating social media link:', error);
    res.status(500).json({ error: error.message });
  }
});

// PUT update social media link
app.put('/api/social-media-links/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const {
      authorName,
      authorEmail,
      platform,
      username,
      url,
      description,
      customLabel,
      displayOrder,
      isActive,
      authorImage
    } = req.body;

    if (isDevelopment) {
      console.log('Social media PUT request:', { id, platform, username });
    }

    // Check if link exists
    const [existing] = await pool.query(
      'SELECT id, author_image, author_name FROM social_media_links WHERE id = ?', 
      [id]
    );
    
    if (existing.length === 0) {
      return res.status(404).json({ error: 'Social media link not found' });
    }

    // Validate required fields
    if (!authorName || !url || !platform) {
      return res.status(400).json({ error: 'Author name, URL, and platform are required' });
    }

    // Validate URL format
    try {
      new URL(url);
    } catch (err) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }

    // Handle image update
    let authorImageToStore = existing[0].author_image;
    
    if (authorImage) {
      const validatedImage = validateSocialMediaImage(authorImage);
      if (!validatedImage) {
        return res.status(400).json({ error: 'Invalid or oversized image. Maximum size is 1MB.' });
      }
      authorImageToStore = JSON.stringify([validatedImage]);
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
         custom_label = ?,
         display_order = ?,
         is_active = ?,
         updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [
        authorName,
        authorEmail || null,
        authorImageToStore,
        platform,
        username || null,
        url,
        description || null,
        customLabel || null,
        displayOrder || 0,
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
        custom_label as customLabel,
        display_order as displayOrder,
        is_active as isActive,
        created_at as createdAt,
        updated_at as updatedAt
      FROM social_media_links 
      WHERE id = ?
    `, [id]);

    const link = updatedLink[0];
    let parsedImage = null;
    try {
      if (link.authorImage) {
        const parsed = JSON.parse(link.authorImage);
        parsedImage = Array.isArray(parsed) ? parsed[0] : parsed;
      }
    } catch (e) {
      parsedImage = link.authorImage;
    }
    link.authorImage = parsedImage;

    res.json({ success: true, data: link });
  } catch (error) {
    console.error('Error updating social media link:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE social media link
app.delete('/api/social-media-links/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const [existing] = await pool.query(
      'SELECT id FROM social_media_links WHERE id = ?', 
      [id]
    );
    
    if (existing.length === 0) {
      return res.status(404).json({ error: 'Social media link not found' });
    }

    await pool.query('DELETE FROM social_media_links WHERE id = ?', [id]);
    
    res.json({ success: true, message: 'Social media link deleted successfully' });
  } catch (error) {
    console.error('Error deleting social media link:', error);
    res.status(500).json({ error: error.message });
  }
});


// ========== EVENT ROUTES WITH BASE64 STORAGE ==========

// Helper function to validate and optimize Base64 images
const validateAndOptimizeBase64 = (base64String) => {
  if (!base64String) return null;
  
  // Check if it's a valid Base64 image
  if (!base64String.startsWith('data:image/')) {
    return null;
  }
  
  // Check size (approximate - Base64 is about 33% larger than binary)
  const sizeInBytes = Buffer.from(base64String.split(',')[1] || '', 'base64').length;
  const sizeInMB = sizeInBytes / (1024 * 1024);
  
  // Reject images larger than 2MB each
  if (sizeInMB > 5) {
    return null;
  }
  
  return base64String;
};

// GET events for display (public frontend) - UPDATED for Base64
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
    
    console.log('📝 Executing display query');
    
    const [rows] = await pool.query(query, params);
    
    // Process events for display
    const events = rows.map(event => {
      // Parse gallery images from JSON (stored as Base64 strings)
      let galleryImages = [];
      try {
        if (event.gallery_images) {
          const parsed = JSON.parse(event.gallery_images);
          galleryImages = Array.isArray(parsed) ? parsed : [];
        }
      } catch (e) {
        console.error('Error parsing gallery images:', e);
        galleryImages = [];
      }
      
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
        gallery_images: galleryImages, // Now contains Base64 strings
        attendees_count: attendeesCount,
        max_attendees: maxAttendees,
        available_seats: availableSeats,
        registration_open: registrationOpen,
        created_at: event.created_at,
        updated_at: event.updated_at
      };
    });
    
    // Count total events for pagination
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

// GET all events with search and filters (ADMIN) - UPDATED for Base64
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
    
    // Parse gallery images from JSON
    const events = rows.map(event => {
      let galleryImages = [];
      try {
        if (event.gallery_images) {
          const parsed = JSON.parse(event.gallery_images);
          galleryImages = Array.isArray(parsed) ? parsed : [];
        }
      } catch (e) {
        console.error('Error parsing gallery images:', e);
        galleryImages = [];
      }
      
      return {
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
        gallery_images: galleryImages, // Base64 strings
        created_at: event.created_at,
        updated_at: event.updated_at
      };
    });
    
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

// POST create event with Base64 images - UPDATED
app.post('/api/events', requireAdmin, async (req, res) => {
  try {
    console.log('📝 Creating new event with Base64 images...');
    
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
      featured,
      galleryImages = []
    } = req.body;

    // Validate required fields
    if (!title || !authorName || !bookstoreLocation || !address || !description || !startDate || !endDate) {
      return res.status(400).json({ 
        success: false, 
        error: 'All fields marked with * are required' 
      });
    }

    // Validate and optimize images
    const validImages = [];
    const invalidImages = [];
    
    for (const img of galleryImages) {
      const validated = validateAndOptimizeBase64(img);
      if (validated) {
        validImages.push(validated);
      } else {
        invalidImages.push(img.substring(0, 50) + '...');
      }
    }
    
    if (invalidImages.length > 0) {
      console.warn(`⚠️ ${invalidImages.length} invalid images were rejected`);
    }
    
    // Check total size (max 10MB for all images combined)
    let totalSize = 0;
    for (const img of validImages) {
      const sizeInBytes = Buffer.from(img.split(',')[1] || '', 'base64').length;
      totalSize += sizeInBytes;
    }
    
    const MAX_TOTAL_SIZE = 10 * 1024 * 1024; // 10MB
    if (totalSize > MAX_TOTAL_SIZE) {
      return res.status(400).json({ 
        success: false, 
        error: 'Total image size exceeds 10MB limit. Please use smaller images or fewer images.' 
      });
    }

    // Parse dates for MySQL
    const parseDateForMySQL = (dateString) => {
      if (!dateString) return null;
      const date = new Date(dateString);
      if (isNaN(date.getTime())) return null;
      return date.toISOString().split('T')[0];
    };
    
    const mysqlStartDate = parseDateForMySQL(startDate);
    const mysqlEndDate = parseDateForMySQL(endDate);

    // Generate display date from start and end dates
    const generateDisplayDate = (start, end) => {
      if (!start) return '';
      
      const startDateObj = new Date(start);
      const endDateObj = end ? new Date(end) : null;
      
      if (isNaN(startDateObj.getTime())) return '';
      
      if (!end || isNaN(endDateObj.getTime()) || start === end) {
        return startDateObj.toLocaleDateString('en-US', { 
          month: 'long', 
          day: 'numeric', 
          year: 'numeric' 
        });
      }
      
      if (startDateObj.getMonth() === endDateObj.getMonth() && startDateObj.getFullYear() === endDateObj.getFullYear()) {
        return `${startDateObj.toLocaleDateString('en-US', { month: 'long' })} ${startDateObj.getDate()}-${endDateObj.getDate()}, ${startDateObj.getFullYear()}`;
      }
      
      return `${startDateObj.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })} - ${endDateObj.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}`;
    };

    const displayDate = generateDisplayDate(mysqlStartDate, mysqlEndDate);

    // Store gallery images as JSON array of Base64 strings
    const galleryImagesJson = JSON.stringify(validImages);

    const [result] = await pool.query(
      `INSERT INTO events 
      (title, date, start_date, end_date, author_name, bookstore_location, 
       address, description, featured_books, event_type, status, featured, gallery_images) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        title,
        displayDate,
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
        galleryImagesJson
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
      gallery_images: validImages // Return Base64 strings
    };

    console.log('✅ Event created successfully with Base64 images:', newEvent.id);

    res.status(201).json({ 
      success: true, 
      data: newEvent,
      message: 'Event created successfully'
    });
  } catch (error) {
    console.error('❌ Error creating event:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to create event',
      details: error.message 
    });
  }
});

// PUT update event with Base64 images - UPDATED
app.put('/api/events/:id', requireAdmin, async (req, res) => {
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
      featured,
      galleryImages = [], // New Base64 images
      existingImages = [] // Existing Base64 images to keep
    } = req.body;

    // Get existing event
    const [existingRows] = await pool.query('SELECT gallery_images FROM events WHERE id = ?', [id]);
    
    if (existingRows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Event not found' 
      });
    }

    // Validate new images
    const validNewImages = [];
    for (const img of galleryImages) {
      const validated = validateAndOptimizeBase64(img);
      if (validated) {
        validNewImages.push(validated);
      }
    }
    
    // Combine existing images (keep the ones user wants) with new valid images
    const allImages = [...existingImages, ...validNewImages];
    
    // Check total size (max 10MB for all images combined)
    let totalSize = 0;
    for (const img of allImages) {
      const sizeInBytes = Buffer.from(img.split(',')[1] || '', 'base64').length;
      totalSize += sizeInBytes;
    }
    
    const MAX_TOTAL_SIZE = 10 * 1024 * 1024; // 10MB
    if (totalSize > MAX_TOTAL_SIZE) {
      return res.status(400).json({ 
        success: false, 
        error: 'Total image size exceeds 10MB limit. Please use smaller images or fewer images.' 
      });
    }

    // Parse dates for MySQL
    const parseDateForMySQL = (dateString) => {
      if (!dateString) return null;
      const date = new Date(dateString);
      if (isNaN(date.getTime())) return null;
      return date.toISOString().split('T')[0];
    };
    
    const mysqlStartDate = parseDateForMySQL(startDate);
    const mysqlEndDate = parseDateForMySQL(endDate);

    // Generate display date
    const generateDisplayDate = (start, end) => {
      if (!start) return '';
      
      const startDateObj = new Date(start);
      const endDateObj = end ? new Date(end) : null;
      
      if (isNaN(startDateObj.getTime())) return '';
      
      if (!end || isNaN(endDateObj.getTime()) || start === end) {
        return startDateObj.toLocaleDateString('en-US', { 
          month: 'long', 
          day: 'numeric', 
          year: 'numeric' 
        });
      }
      
      if (startDateObj.getMonth() === endDateObj.getMonth() && startDateObj.getFullYear() === endDateObj.getFullYear()) {
        return `${startDateObj.toLocaleDateString('en-US', { month: 'long' })} ${startDateObj.getDate()}-${endDateObj.getDate()}, ${startDateObj.getFullYear()}`;
      }
      
      return `${startDateObj.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })} - ${endDateObj.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}`;
    };

    const displayDate = generateDisplayDate(mysqlStartDate, mysqlEndDate);

    // Prepare update data
    const updateData = {
      title: title ? title.trim() : undefined,
      date: displayDate,
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
      gallery_images: JSON.stringify(allImages) // Store as JSON array of Base64 strings
    };

    // Remove undefined values
    Object.keys(updateData).forEach(key => {
      if (updateData[key] === undefined) {
        delete updateData[key];
      }
    });

    if (Object.keys(updateData).length === 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'No data provided for update' 
      });
    }

    const setClause = Object.keys(updateData).map(field => `${field} = ?`).join(', ');
    const values = Object.values(updateData);
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

    // Parse gallery images
    let responseGalleryImages = [];
    try {
      if (updatedEvent.gallery_images) {
        responseGalleryImages = JSON.parse(updatedEvent.gallery_images);
        if (!Array.isArray(responseGalleryImages)) {
          responseGalleryImages = [];
        }
      }
    } catch (e) {
      console.error('Error parsing gallery images:', e);
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

    console.log('✅ Event updated successfully with Base64 images:', id);

    res.json({ 
      success: true, 
      data: responseEvent,
      message: 'Event updated successfully' 
    });
  } catch (error) {
    console.error('❌ Error updating event:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to update event',
      details: error.message 
    });
  }
});

// DELETE route for removing specific image by index - UPDATED
app.delete('/api/events/:id/image/:index', requireAdmin, async (req, res) => {
  try {
    const { id, index } = req.params;
    
    // Get current gallery images
    const [rows] = await pool.query('SELECT gallery_images FROM events WHERE id = ?', [id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Event not found' });
    }
    
    let galleryImages = [];
    try {
      if (rows[0].gallery_images) {
        galleryImages = JSON.parse(rows[0].gallery_images);
        if (!Array.isArray(galleryImages)) {
          galleryImages = [];
        }
      }
    } catch (e) {
      console.error('Error parsing gallery images:', e);
      galleryImages = [];
    }
    
    // Remove image at specified index
    const imageIndex = parseInt(index);
    if (imageIndex >= 0 && imageIndex < galleryImages.length) {
      galleryImages.splice(imageIndex, 1);
    } else {
      return res.status(400).json({ success: false, error: 'Invalid image index' });
    }
    
    // Update database
    await pool.query(
      'UPDATE events SET gallery_images = ? WHERE id = ?',
      [JSON.stringify(galleryImages), id]
    );
    
    res.json({ 
      success: true, 
      message: 'Image removed successfully',
      images_remaining: galleryImages.length
    });
  } catch (error) {
    console.error('Error removing image:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// DELETE event
app.delete('/api/events/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const [result] = await pool.query('DELETE FROM events WHERE id = ?', [id]);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Event not found' 
      });
    }
    
    res.json({ 
      success: true, 
      message: 'Event deleted successfully' 
    });
  } catch (error) {
    console.error('Error deleting event:', error);
    res.status(500).json({ success: false, error: error.message });
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
    
    // Check event capacity
    const [registrationCountRows] = await pool.query(
      `SELECT COUNT(*) as count FROM event_registrations 
       WHERE event_id = ? AND status IN ('pending', 'confirmed')`,
      [id]
    );
    
    const registrationCount = registrationCountRows[0].count;
    const maxCapacity = 100; // Default capacity
    
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

// Add this to your server.js file - Reviews API Routes

// Get reviews for a service with pagination
app.get('/api/reviews/:section/:serviceSlug', async (req, res) => {
  try {
    const { section, serviceSlug } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 3;
    const offset = (page - 1) * limit;

    // Get total count of reviews for this service
    const [countResult] = await pool.query(
      'SELECT COUNT(*) as total FROM service_reviews WHERE service_slug = ? AND section = ?',
      [serviceSlug, section]
    );

    // Get paginated reviews ordered by most recent first
    const [reviews] = await pool.query(
      `SELECT id, name, rating, text, created_at 
       FROM service_reviews 
       WHERE service_slug = ? AND section = ? 
       ORDER BY created_at DESC 
       LIMIT ? OFFSET ?`,
      [serviceSlug, section, limit, offset]
    );

    res.json({
      success: true,
      data: reviews,
      pagination: {
        currentPage: page,
        totalPages: Math.ceil(countResult[0].total / limit),
        totalItems: countResult[0].total,
        itemsPerPage: limit
      }
    });
  } catch (error) {
    console.error('Error fetching reviews:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create a new review
app.post('/api/reviews', async (req, res) => {
  try {
    const { service_slug, section, name, email, rating, text, recaptcha } = req.body;

    // Validate required fields
    if (!service_slug || !section || !name || !email) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields' 
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid email format' 
      });
    }

    // Validate rating if provided
    if (rating && (rating < 1 || rating > 5)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Rating must be between 1 and 5' 
      });
    }

    // Insert review into database
    const [result] = await pool.query(
      `INSERT INTO service_reviews (service_slug, section, name, email, rating, text) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [service_slug, section, name, email, rating || null, text || null]
    );

    res.json({
      success: true,
      message: 'Review submitted successfully',
      data: {
        id: result.insertId,
        service_slug,
        section,
        name,
        email,
        rating,
        text,
        created_at: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Error creating review:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get average rating for a service
app.get('/api/reviews/:section/:serviceSlug/average', async (req, res) => {
  try {
    const { section, serviceSlug } = req.params;

    const [result] = await pool.query(
      `SELECT 
        COUNT(*) as total_reviews,
        COALESCE(AVG(rating), 0) as average_rating,
        COUNT(CASE WHEN rating IS NOT NULL THEN 1 END) as ratings_count
       FROM service_reviews 
       WHERE service_slug = ? AND section = ?`,
      [serviceSlug, section]
    );

    res.json({
      success: true,
      data: {
        total_reviews: result[0].total_reviews,
        average_rating: parseFloat(result[0].average_rating) || 0,
        ratings_count: result[0].ratings_count
      }
    });
  } catch (error) {
    console.error('Error fetching average rating:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Delete a review (optional - admin only)
app.delete('/api/reviews/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const [result] = await pool.query(
      'DELETE FROM service_reviews WHERE id = ?',
      [id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        error: 'Review not found' 
      });
    }

    res.json({ 
      success: true, 
      message: 'Review deleted successfully' 
    });
  } catch (error) {
    console.error('Error deleting review:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});


const bcrypt = require('bcrypt');

// ========== JWT AUTHENTICATION MIDDLEWARE ==========
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ success: false, error: 'Access token required' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// ========== AUTHENTICATION ROUTES ==========

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email and password are required' 
            });
        }

        // Query the database for the user
        const [users] = await pool.query(
            'SELECT id, email, name, password_hash, role, is_active FROM agents WHERE email = ?',
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid email or password' 
            });
        }

        const user = users[0];

        // Check if user is active
        if (!user.is_active) {
            return res.status(401).json({ 
                success: false, 
                error: 'Account is disabled. Please contact support.' 
            });
        }

        // Compare password
        const isValidPassword = await bcrypt.compare(password, user.password_hash);

        if (!isValidPassword) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid email or password' 
            });
        }

        // Update last login time
        await pool.query(
            'UPDATE agents SET last_login = NOW() WHERE id = ?',
            [user.id]
        );

        // Generate JWT token
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Return success response
        res.json({
            success: true,
            message: 'Login successful',
            data: {
                token: token,
                user: {
                    id: user.id,
                    email: user.email,
                    name: user.name,
                    role: user.role
                }
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
    try {
        const { firstName, lastName, email, password, role } = req.body;

        // Validate required fields
        if (!firstName || !lastName || !email || !password) {
            return res.status(400).json({ 
                success: false, 
                error: 'All fields are required' 
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid email format' 
            });
        }

        // Validate password length
        if (password.length < 6) {
            return res.status(400).json({ 
                success: false, 
                error: 'Password must be at least 6 characters long' 
            });
        }

        // Check if user already exists
        const [existingUsers] = await pool.query(
            'SELECT id FROM agents WHERE email = ?',
            [email]
        );

        if (existingUsers.length > 0) {
            return res.status(409).json({ 
                success: false, 
                error: 'Email already registered' 
            });
        }

        // Hash the password
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Insert the new agent
        const [result] = await pool.query(
            `INSERT INTO agents (email, name, first_name, last_name, password_hash, role, is_active) 
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [email, `${firstName} ${lastName}`, firstName, lastName, passwordHash, role || 'agent', true]
        );

        // Return success response
        res.json({
            success: true,
            message: 'Account created successfully',
            data: {
                id: result.insertId,
                email: email,
                name: `${firstName} ${lastName}`,
                role: role || 'agent'
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// Get current user info (protected route)
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const [users] = await pool.query(
            'SELECT id, email, name, first_name, last_name, role, is_active, created_at FROM agents WHERE id = ?',
            [req.user.id]
        );
        
        if (users.length === 0) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }
        
        res.json({ success: true, data: users[0] });
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Logout endpoint - no authentication needed
app.post('/api/auth/logout', (req, res) => {
    // For JWT, logout is purely client-side
    // Just return success
    res.json({ success: true, message: 'Logged out successfully' });
});









// ========== AGENT CHAT ROUTES ==========

// Get all conversations for agent
app.get('/api/agent/conversations', authenticateToken, async (req, res) => {
  try {
    const agentId = req.user.id;
    
    // Check database connection
    const isConnected = await ensureConnection();
    if (!isConnected) {
      return res.status(503).json({ 
        success: false, 
        error: 'Database connection unavailable' 
      });
    }
    
    // Get all visitors assigned to this agent
    const [visitors] = await pool.query(
      `SELECT v.id, v.email, v.name, v.topic, v.conversation_id, 
              v.assigned_at, v.created_at, v.updated_at
       FROM visitors v 
       WHERE v.agent_id = ? 
         AND (v.completed_at IS NULL OR v.completed_at = '0000-00-00 00:00:00' OR v.completed_at = '')
       ORDER BY v.updated_at DESC`,
      [agentId]
    );
    
    const conversations = [];
    
    for (const visitor of visitors) {
      // Get all messages for this visitor - ORDER BY created_at ASC (oldest first)
      const [messages] = await pool.query(
        `SELECT m.id, m.message, m.is_agent, m.agent_id, m.created_at, m.conversation_id,
                a.name as agent_name
         FROM visitor_messages m
         LEFT JOIN agents a ON m.agent_id = a.id
         WHERE m.visitor_email = ? AND m.conversation_id = ?
         ORDER BY m.created_at ASC`,
        [visitor.email, visitor.conversation_id]
      );
      
      // Format messages with consistent timestamp format
      const formattedMessages = messages.map(msg => ({
        id: msg.id,
        message: msg.message,
        text: msg.message,
        isAgent: msg.is_agent === 1,
        timestamp: msg.created_at ? new Date(msg.created_at).toISOString() : new Date().toISOString(),
        agent_id: msg.agent_id,
        conversation_id: msg.conversation_id,
        agent_name: msg.agent_name || (msg.is_agent ? 'Agent' : null)
      }));
      
      // Calculate unread count
      let unreadCount = 0;
      const lastAgentMessage = [...formattedMessages].reverse().find(m => m.isAgent);
      if (lastAgentMessage) {
        unreadCount = formattedMessages.filter(m => 
          !m.isAgent && new Date(m.timestamp) > new Date(lastAgentMessage.timestamp)
        ).length;
      } else {
        unreadCount = formattedMessages.filter(m => !m.isAgent).length;
      }
      
      const hasAgentResponded = formattedMessages.some(msg => msg.isAgent);
      const hasClientMessages = formattedMessages.some(msg => !msg.isAgent);
      
      conversations.push({
        id: visitor.id,
        email: visitor.email,
        name: visitor.name || visitor.email,
        topic: visitor.topic,
        chatKey: visitor.email,
        conversation_id: visitor.conversation_id,
        messages: formattedMessages,
        last_message_at: messages.length > 0 ? messages[messages.length - 1].created_at : visitor.created_at,
        needsWelcome: hasClientMessages && !hasAgentResponded,
        unread_count: unreadCount
      });
    }
    
    conversations.sort((a, b) => new Date(b.last_message_at) - new Date(a.last_message_at));
    
    res.json({ success: true, data: conversations });
  } catch (error) {
    console.error('Error fetching conversations:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Send message as agent
app.post('/api/agent/messages', authenticateToken, async (req, res) => {
    const { visitor_email, message, conversation_id } = req.body;
    const agentId = req.user.id;
    
    if (!visitor_email || !message || !conversation_id) {
        return res.status(400).json({ 
            success: false, 
            error: 'Missing required fields: visitor_email, message, conversation_id'
        });
    }
    
    try {
        // Get agent name
        const [agent] = await pool.query(
            'SELECT name FROM agents WHERE id = ?',
            [agentId]
        );
        
        // Insert message with MySQL NOW()
        const [result] = await pool.query(
            `INSERT INTO visitor_messages (visitor_email, message, is_agent, agent_id, created_at, conversation_id) 
             VALUES (?, ?, 1, ?, NOW(), ?)`,
            [visitor_email, message, agentId, conversation_id]
        );
        
        // Get the created_at timestamp from MySQL
        const [newMessage] = await pool.query(
            'SELECT created_at FROM visitor_messages WHERE id = ?',
            [result.insertId]
        );
        
        // Update visitor's updated_at
        await pool.query(
            'UPDATE visitors SET updated_at = NOW() WHERE email = ? AND conversation_id = ?',
            [visitor_email, conversation_id]
        );
        
        // Return consistent timestamp format
        const timestamp = new Date(newMessage[0].created_at).toISOString();
        
        res.json({
            success: true,
            data: {
                id: result.insertId,
                message: message,
                is_agent: true,
                agent_id: agentId,
                agent_name: agent[0]?.name || 'Agent',
                created_at: timestamp,
                timestamp: timestamp,
                conversation_id: conversation_id,
                visitor_email: visitor_email
            }
        });
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Mark conversation as read
app.post('/api/agent/conversations/:email/read', authenticateToken, async (req, res) => {
    const { email } = req.params;
    const agentId = req.user.id;
    
    try {
        await pool.query(
            `UPDATE visitors 
             SET last_read_at = NOW(), updated_at = NOW() 
             WHERE email = ? AND agent_id = ? AND completed_at IS NULL`,
            [email, agentId]
        );
        
        res.json({ success: true, message: 'Marked as read' });
    } catch (error) {
        console.error('Error marking as read:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========== VISITOR CHAT ROUTES ==========

// Get messages for a conversation
app.get('/api/visitor/messages/:conversationId', async (req, res) => {
  try {
    const { conversationId } = req.params;
    
    const isConnected = await ensureConnection();
    if (!isConnected) {
      return res.status(503).json({ 
        success: false, 
        error: 'Database connection unavailable' 
      });
    }
    
    const [messages] = await pool.query(
      `SELECT m.id, m.visitor_email, m.message, m.is_agent, m.agent_id, m.created_at, m.conversation_id,
              a.name as agent_name
       FROM visitor_messages m
       LEFT JOIN agents a ON m.agent_id = a.id
       WHERE m.conversation_id = ? 
       ORDER BY m.created_at ASC`,
      [conversationId]
    );
    
    // Format messages with consistent timestamp
    const formattedMessages = messages.map(msg => ({
      id: msg.id,
      visitor_email: msg.visitor_email,
      message: msg.message,
      is_agent: msg.is_agent === 1,
      agent_id: msg.agent_id,
      conversation_id: msg.conversation_id,
      created_at: msg.created_at ? new Date(msg.created_at).toISOString() : new Date().toISOString(),
      timestamp: msg.created_at ? new Date(msg.created_at).toISOString() : new Date().toISOString(),
      agent_name: msg.agent_name
    }));
    
    res.json({ success: true, data: formattedMessages });
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Create or update visitor
app.post('/api/visitors', async (req, res) => {
  try {
    const { email, name, topic, conversation_id } = req.body;
    
    if (!email || !conversation_id) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields: email, conversation_id' 
      });
    }
    
    const isConnected = await ensureConnection();
    if (!isConnected) {
      return res.status(503).json({ 
        success: false, 
        error: 'Database connection unavailable' 
      });
    }
    
    // Generate a default name from email if not provided
    let visitorName = name;
    if (!visitorName || visitorName === 'null' || visitorName === 'undefined') {
      visitorName = email.split('@')[0] || 'Visitor';
      visitorName = visitorName.replace(/[^a-zA-Z0-9]/g, ' ').trim();
      if (visitorName.length === 0) visitorName = 'Visitor';
      visitorName = visitorName.charAt(0).toUpperCase() + visitorName.slice(1);
    }
    
    // Check if visitor exists with this conversation
    const [existing] = await pool.query(
      'SELECT id, agent_id, conversation_id FROM visitors WHERE email = ? AND conversation_id = ?',
      [email, conversation_id]
    );
    
    let visitorId;
    if (existing.length > 0) {
      // Update existing
      await pool.query(
        `UPDATE visitors 
         SET topic = ?, name = ?, updated_at = NOW() 
         WHERE email = ? AND conversation_id = ?`,
        [topic || null, visitorName, email, conversation_id]
      );
      visitorId = existing[0].id;
    } else {
      // Insert new
      const [result] = await pool.query(
        `INSERT INTO visitors (email, name, topic, conversation_id, created_at, updated_at) 
         VALUES (?, ?, ?, ?, NOW(), NOW())`,
        [email, visitorName, topic || null, conversation_id]
      );
      visitorId = result.insertId;
    }
    
    res.json({ 
      success: true, 
      data: { 
        id: visitorId, 
        email, 
        name: visitorName, 
        topic, 
        conversation_id 
      } 
    });
  } catch (error) {
    console.error('Error creating/updating visitor:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get visitor by email and conversation
app.get('/api/visitors/:email', async (req, res) => {
    try {
        const { email } = req.params;
        const { conversation_id } = req.query;
        
        let query = 'SELECT * FROM visitors WHERE email = ?';
        const params = [decodeURIComponent(email)];
        
        if (conversation_id) {
            query += ' AND conversation_id = ?';
            params.push(conversation_id);
        }
        
        query += ' ORDER BY created_at DESC LIMIT 1';
        
        const [visitors] = await pool.query(query, params);
        
        if (visitors.length === 0) {
            return res.status(404).json({ success: false, error: 'Visitor not found' });
        }
        
        // Format dates
        const visitor = visitors[0];
        if (visitor.created_at) visitor.created_at = new Date(visitor.created_at).toISOString();
        if (visitor.updated_at) visitor.updated_at = new Date(visitor.updated_at).toISOString();
        if (visitor.assigned_at) visitor.assigned_at = new Date(visitor.assigned_at).toISOString();
        
        res.json({ success: true, data: visitor });
    } catch (error) {
        console.error('Error fetching visitor:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Assign agent to visitor
app.post('/api/visitors/assign-agent', async (req, res) => {
    try {
        const { email, topic, conversation_id } = req.body;
        
        if (!email || !conversation_id) {
            return res.status(400).json({ 
                success: false, 
                error: 'Missing required fields' 
            });
        }
        
        // Get available agents (least assigned)
        const [agents] = await pool.query(
            `SELECT a.*, COUNT(v.id) as assigned_count 
             FROM agents a 
             LEFT JOIN visitors v ON a.id = v.agent_id AND v.completed_at IS NULL 
             WHERE a.role = 'agent' AND a.is_active = 1
             GROUP BY a.id 
             ORDER BY assigned_count ASC, a.last_assigned_at ASC 
             LIMIT 1`,
            []
        );
        
        if (agents.length === 0) {
            return res.status(404).json({ success: false, error: 'No agents available' });
        }
        
        const assignedAgent = agents[0];
        
        // Check if visitor exists
        const [existing] = await pool.query(
            'SELECT id FROM visitors WHERE email = ? AND conversation_id = ?',
            [email, conversation_id]
        );
        
        if (existing.length > 0) {
            // Update existing visitor with agent
            await pool.query(
                `UPDATE visitors 
                 SET agent_id = ?, topic = ?, assigned_at = NOW(), updated_at = NOW() 
                 WHERE email = ? AND conversation_id = ?`,
                [assignedAgent.id, topic, email, conversation_id]
            );
        } else {
            // Create new visitor with agent
            await pool.query(
                `INSERT INTO visitors (email, topic, conversation_id, agent_id, assigned_at, created_at, updated_at) 
                 VALUES (?, ?, ?, ?, NOW(), NOW(), NOW())`,
                [email, topic, conversation_id, assignedAgent.id]
            );
        }
        
        // Update agent's last assigned time
        await pool.query(
            'UPDATE agents SET last_assigned_at = NOW() WHERE id = ?',
            [assignedAgent.id]
        );
        
        res.json({ 
            success: true, 
            data: { 
                agent: {
                    id: assignedAgent.id,
                    name: assignedAgent.name,
                    email: assignedAgent.email
                }
            } 
        });
    } catch (error) {
        console.error('Error assigning agent:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Save visitor message
app.post('/api/visitor/messages', async (req, res) => {
  try {
    const { visitor_email, message, is_agent, agent_id, conversation_id } = req.body;
    
    if (!visitor_email || !message || !conversation_id) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields: visitor_email, message, conversation_id' 
      });
    }
    
    const isConnected = await ensureConnection();
    if (!isConnected) {
      return res.status(503).json({ 
        success: false, 
        error: 'Database connection unavailable' 
      });
    }
    
    const [result] = await pool.query(
      `INSERT INTO visitor_messages (visitor_email, message, is_agent, agent_id, created_at, conversation_id) 
       VALUES (?, ?, ?, ?, NOW(), ?)`,
      [visitor_email, message, is_agent ? 1 : 0, agent_id || null, conversation_id]
    );
    
    // Get the created_at timestamp
    const [newMessage] = await pool.query(
      'SELECT created_at FROM visitor_messages WHERE id = ?',
      [result.insertId]
    );
    
    // Update visitor's updated_at
    await pool.query(
      'UPDATE visitors SET updated_at = NOW() WHERE email = ? AND conversation_id = ?',
      [visitor_email, conversation_id]
    );
    
    const timestamp = new Date(newMessage[0].created_at).toISOString();
    
    res.json({
      success: true,
      data: {
        id: result.insertId,
        visitor_email,
        message,
        is_agent: is_agent || false,
        agent_id: agent_id || null,
        conversation_id,
        created_at: timestamp,
        timestamp: timestamp
      }
    });
  } catch (error) {
    console.error('Error saving message:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Get agent by ID
app.get('/api/agents/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        const [agents] = await pool.query(
            'SELECT id, name, email, role FROM agents WHERE id = ?',
            [id]
        );
        
        if (agents.length === 0) {
            return res.status(404).json({ success: false, error: 'Agent not found' });
        }
        
        res.json({ success: true, data: agents[0] });
    } catch (error) {
        console.error('Error fetching agent:', error);
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
Frontend: http://192.168.68.76:5177
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