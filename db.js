const mysql = require('mysql2');
require('dotenv').config();

// Create connection pool with better configuration
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'bookstore_db',
  waitForConnections: true,
  connectionLimit: 50,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000
});

// Promisify for async/await
const promisePool = pool.promise();

// Test connection
const testConnection = async () => {
  try {
    const [rows] = await promisePool.query('SELECT 1 + 1 AS result');
    console.log('✅ Database connected successfully');
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    console.log('💡 Make sure:');
    console.log('   1. MySQL is running');
    console.log('   2. Database "bookstore_db" exists');
    console.log('   3. Username/password are correct in .env file');
    return false;
  }
};

// Health check function to ensure connection is alive
const ensureConnection = async () => {
  try {
    await promisePool.query('SELECT 1');
    console.log('✅ Database connection healthy');
    return true;
  } catch (error) {
    console.error('❌ Database connection error:', error.message);
    // Try to get a new connection
    try {
      const connection = await promisePool.getConnection();
      connection.release();
      console.log('✅ Database reconnected successfully');
      return true;
    } catch (reconnectError) {
      console.error('❌ Failed to reconnect:', reconnectError.message);
      return false;
    }
  }
};

// Helper function to parse dates for MySQL
const parseDateForMySQL = (dateString) => {
  if (!dateString) return null;
  
  try {
    let date;
    if (dateString.includes('/')) {
      const parts = dateString.split('/');
      if (parts.length === 3) {
        // Check if it's YYYY/MM/DD
        if (parts[0].length === 4) {
          date = new Date(`${parts[0]}-${parts[1]}-${parts[2]}`);
        } else {
          // Assume MM/DD/YYYY
          date = new Date(`${parts[2]}-${parts[0]}-${parts[1]}`);
        }
      } else {
        date = new Date(dateString);
      }
    } else {
      date = new Date(dateString);
    }
    
    if (isNaN(date.getTime())) {
      console.warn('Invalid date:', dateString);
      return null;
    }
    
    return date.toISOString().split('T')[0];
  } catch (error) {
    console.error('Error parsing date:', dateString, error);
    return null;
  }
};

// Export the promise pool and functions
module.exports = {
  pool: promisePool,
  testConnection,
  ensureConnection,
  parseDateForMySQL
};