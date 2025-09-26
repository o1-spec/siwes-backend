const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// PostgreSQL connection pool
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).send('Access denied');
  try {
    const decoded = jwt.verify(token, 'secret_key');
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).send('Invalid token');
  }
};

// ===============================
// Test Route
// ===============================
app.get('/', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ message: 'Connected to PostgreSQL!', time: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database connection error');
  }
});

// ===============================
// USERS ROUTES
// ===============================
app.get('/users', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users ORDER BY user_id ASC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching users');
  }
});

app.post('/users', authenticate, async (req, res) => {
  const { full_name, email, role } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO users (full_name, email, role) VALUES ($1, $2, $3) RETURNING *',
      [full_name, email, role]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error adding user');
  }
});

app.get('/users/me', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT user_id, full_name, email, role FROM users WHERE user_id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).send('User not found');
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching user');
  }
});

app.put('/users/me', authenticate, async (req, res) => {
  const { full_name, email, password } = req.body;
  try {
    let query = 'UPDATE users SET full_name = $1, email = $2';
    let params = [full_name, email];
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      query += ', password = $3';
      params.push(hashedPassword);
    }
    query +=
      ' WHERE user_id = $' +
      (params.length + 1) +
      ' RETURNING user_id, full_name, email, role';
    params.push(req.user.id);
    const result = await pool.query(query, params);
    if (result.rows.length === 0) return res.status(404).send('User not found');
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating user');
  }
});

app.put('/users/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { full_name, email, role } = req.body;
  try {
    const result = await pool.query(
      'UPDATE users SET full_name = $1, email = $2, role = $3 WHERE user_id = $4 RETURNING *',
      [full_name, email, role, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).send('User not found');
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating user');
  }
});

app.delete('/users/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM users WHERE user_id = $1', [id]);
    res.send('User deleted');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting user');
  }
});

// ===============================
// BOOKS ROUTES
// ===============================
app.get('/books', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM books ORDER BY book_id ASC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching books');
  }
});

app.post('/books', authenticate, async (req, res) => {
  const { title, author, published_year, isbn, copies_available } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO books (title, author, published_year, isbn, copies_available) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [title, author, published_year, isbn, copies_available || 1]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error adding book');
  }
});

app.put('/books/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { title, author, published_year, isbn, copies_available } = req.body;
  try {
    const result = await pool.query(
      'UPDATE books SET title = $1, author = $2, published_year = $3, isbn = $4, copies_available = $5 WHERE book_id = $6 RETURNING *',
      [title, author, published_year, isbn, copies_available, id]
    );
    if (result.rows.length === 0) {
      return res.status(404).send('Book not found');
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating book');
  }
});

app.delete('/books/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM books WHERE book_id = $1', [id]);
    res.send('Book deleted');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting book');
  }
});

// ===============================
// BORROW RECORDS ROUTES
// ===============================
app.get('/borrow_records', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT br.record_id, u.full_name, b.title, br.borrow_date, br.due_date, br.return_date, br.status
      FROM borrow_records br
      JOIN users u ON br.user_id = u.user_id
      JOIN books b ON br.book_id = b.book_id
      ORDER BY br.record_id ASC
    `);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching borrow records');
  }
});

app.post('/borrow_records', authenticate, async (req, res) => {
  const { user_id, book_id, due_date } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO borrow_records (user_id, book_id, due_date) VALUES ($1, $2, $3) RETURNING *',
      [user_id, book_id, due_date]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error creating borrow record');
  }
});

app.put('/borrow_records/:id/return', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'UPDATE borrow_records SET return_date = CURRENT_DATE, status = $1 WHERE record_id = $2 RETURNING *',
      ['returned', id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating borrow record');
  }
});

app.delete('/borrow_records/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM borrow_records WHERE record_id = $1', [id]);
    res.send('Borrow record deleted');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting borrow record');
  }
});

// ===============================
// REPORTS ROUTES
// ===============================
app.get('/reports/most-borrowed', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT b.title, COUNT(br.record_id) AS borrow_count
      FROM borrow_records br
      JOIN books b ON br.book_id = b.book_id
      GROUP BY b.book_id, b.title
      ORDER BY borrow_count DESC
      LIMIT 10
    `);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching most borrowed books');
  }
});

app.get('/reports/active-users', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.full_name, COUNT(br.record_id) AS borrow_count
      FROM borrow_records br
      JOIN users u ON br.user_id = u.user_id
      GROUP BY u.user_id, u.full_name
      ORDER BY borrow_count DESC
      LIMIT 10
    `);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching active users');
  }
});

app.get('/reports/overdue', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.full_name, b.title, br.due_date,
             (CURRENT_DATE - br.due_date) AS overdue_days,  -- Direct calculation
             ((CURRENT_DATE - br.due_date) * 1) AS fine     -- $1 per day
      FROM borrow_records br
      JOIN users u ON br.user_id = u.user_id
      JOIN books b ON br.book_id = b.book_id
      WHERE br.return_date IS NULL AND br.due_date < CURRENT_DATE
    `);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching overdue books');
  }
});

// ===============================
// AUTH ROUTES
// ===============================
app.post('/register', async (req, res) => {
  const { full_name, email, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (full_name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *',
      [full_name, email, hashedPassword, role]
    );
    res.json({ message: 'User registered successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error registering user');
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [
      email,
    ]);
    if (result.rows.length === 0) return res.status(401).send('User not found');
    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).send('Invalid password');
    const token = jwt.sign(
      { id: user.user_id, role: user.role },
      'secret_key',
      { expiresIn: '1h' }
    );
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).send('Login error');
  }
});

// ===============================
// START SERVER
// ===============================
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
