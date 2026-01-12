const mysql = require('mysql2');
require('dotenv').config();

// Create connection pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || '',
  user: process.env.DB_USER || '',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'bookstore_db',
  waitForConnections: true,
  connectionLimit: 50,
  queueLimit: 0
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

// Export the promise pool and test function
module.exports = {
  pool: promisePool,
  testConnection
};