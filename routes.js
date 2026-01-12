const express = require('express');
const router = express.Router();
const { pool } = require('./db');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// ========== AUTHENTICATION MIDDLEWARE ==========

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

// ========== AUTH ROUTES ==========

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (email === 'admin@bookstore.com' && password === 'admin123') {
      req.session.userId = 1;
      req.session.email = email;
      req.session.role = 'admin';
      req.session.name = 'Admin User';
      
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
      res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Logout
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ success: false, error: 'Logout failed' });
    }
    res.json({ success: true, message: 'Logged out successfully' });
  });
});

// Check auth status
router.get('/auth/check', (req, res) => {
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

// ========== ADMIN DASHBOARD ROUTES ==========

// Admin dashboard stats
router.get('/admin/dashboard', requireAdmin, async (req, res) => {
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

// ========== BOOKSTORE ROUTES ==========

// GET all bookstores
router.get('/bookstores', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM bookstores ORDER BY created_at DESC');
    res.json({ success: true, data: rows });
  } catch (error) {
    console.error('Error fetching bookstores:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET single bookstore by ID
router.get('/bookstores/:id', async (req, res) => {
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
router.post('/bookstores', requireAdmin, (req, res, next) => {
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
router.put('/bookstores/:id', requireAdmin, (req, res, next) => {
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
router.delete('/bookstores/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    await pool.query('DELETE FROM bookstores WHERE id = ?', [id]);
    
    res.json({ success: true, message: 'Bookstore deleted successfully' });
  } catch (error) {
    console.error('Error deleting bookstore:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ========== AUTHOR ROUTES ==========

// GET all authors (for admin panel)
router.get('/authors', requireAdmin, async (req, res) => {
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
router.get('/authors/:id', async (req, res) => {
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
router.get('/authors/:id/books', async (req, res) => {
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
router.put('/authors/:id', requireAdmin, async (req, res) => {
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
router.delete('/authors/:id', requireAdmin, async (req, res) => {
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
router.get('/authors/bookstore/:bookstoreId', async (req, res) => {
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
router.post('/authors', requireAdmin, async (req, res) => {
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

// ========== BOOK ROUTES ==========

// GET all books (for admin panel)
router.get('/books', requireAdmin, async (req, res) => {
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
router.put('/books/:id', requireAdmin, async (req, res) => {
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
      image_url  // Add this!
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
router.delete('/books/:id', requireAdmin, async (req, res) => {
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
router.get('/books/bookstore/:bookstoreId', async (req, res) => {
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
router.get('/books/author/:authorId', async (req, res) => {
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
router.post('/books/upload-image', requireAdmin, (req, res, next) => {
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
router.post('/books', requireAdmin, async (req, res) => {
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

// ========== HEALTH CHECK ==========

router.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ 
      success: true, 
      message: 'API is running',
      database: 'connected'
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'API is running',
      database: 'disconnected',
      error: error.message 
    });
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
router.get('/social-media-links', async (req, res) => {
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
router.get('/social-media-links/:id', async (req, res) => {
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
router.post('/social-media-links', uploadSocialMedia.single('authorImage'), async (req, res) => {
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
    console.log('Social media POST request body:', req.body);
    console.log('Social media POST file:', req.file);

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
router.put('/social-media-links/:id', uploadSocialMedia.single('authorImage'), async (req, res) => {
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

    console.log('Social media PUT request body:', req.body);
    console.log('Social media PUT file:', req.file);

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
router.delete('/social-media-links/:id', async (req, res) => {
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
router.get('/social-media-links/author/:name', async (req, res) => {
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
router.get('/social-media-links/platform/:platform', async (req, res) => {
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
router.patch('/social-media-links/:id/status', async (req, res) => {
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
router.use('/uploads/social-media', express.static('uploads/social-media'));

module.exports = router;