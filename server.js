const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
const corsOptions = {
  origin: ['http://localhost:5173', 'https://siwes-lms.vercel.app'],
  credentials: true,
};
app.use(cors(corsOptions));
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅ Connected to MongoDB successfully'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// ===============================
// MONGOOSE SCHEMAS & MODELS
// ===============================

// User Schema
const userSchema = new mongoose.Schema({
  full_name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'student', enum: ['student', 'admin', 'librarian'] },
  created_at: { type: Date, default: Date.now }
});

// Book Schema
const bookSchema = new mongoose.Schema({
  title: { type: String, required: true },
  author: { type: String, required: true },
  published_year: { type: Number },
  isbn: { type: String },
  copies_available: { type: Number, default: 1 },
  created_at: { type: Date, default: Date.now }
});

// Borrow Record Schema
const borrowRecordSchema = new mongoose.Schema({
  user_name: { type: String, required: true },
  book_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Book', required: true },
  borrow_date: { type: Date, default: Date.now },
  due_date: { type: Date, required: true },
  return_date: { type: Date },
  status: { type: String, default: 'borrowed', enum: ['borrowed', 'returned'] },
  created_at: { type: Date, default: Date.now }
});

// Stats History Schema
const statsHistorySchema = new mongoose.Schema({
  date: { type: Date, default: Date.now, unique: true },
  total_books: { type: Number, default: 0 },
  total_users: { type: Number, default: 0 },
  active_borrows: { type: Number, default: 0 },
  overdue_books: { type: Number, default: 0 }
});

// Models
const User = mongoose.model('User', userSchema);
const Book = mongoose.model('Book', bookSchema);
const BorrowRecord = mongoose.model('BorrowRecord', borrowRecordSchema);
const StatsHistory = mongoose.model('StatsHistory', statsHistorySchema);

// ===============================
// MIDDLEWARE
// ===============================
const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).send('Access denied');
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).send('Invalid token');
  }
};

// ===============================
// TEST ROUTE
// ===============================
app.get('/', async (req, res) => {
  try {
    const dbState = mongoose.connection.readyState;
    const states = ['disconnected', 'connected', 'connecting', 'disconnecting'];
    res.json({
      message: 'Connected to MongoDB!',
      status: states[dbState],
      time: new Date()
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database connection error');
  }
});

// ===============================
// AUTH ROUTES
// ===============================
app.post('/register', async (req, res) => {
  const { full_name, email, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      full_name,
      email,
      password: hashedPassword,
      role: role || 'student'
    });
    await user.save();
    res.json({ message: 'User registered successfully' });
  } catch (err) {
    console.error(err);
    if (err.code === 11000) {
      return res.status(400).send('Email already exists');
    }
    res.status(500).send('Error registering user');
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).send('User not found');
    
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).send('Invalid password');
    
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).send('Login error');
  }
});

app.post('/logout', authenticate, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

// ===============================
// USERS ROUTES
// ===============================
app.get('/users', authenticate, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ _id: 1 });
    const formattedUsers = users.map(user => ({
      user_id: user._id,
      full_name: user.full_name,
      email: user.email,
      role: user.role,
      created_at: user.created_at
    }));
    res.json(formattedUsers);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching users');
  }
});

app.post('/users', authenticate, async (req, res) => {
  const { full_name, email, role } = req.body;
  try {
    const defaultPassword = await bcrypt.hash('password123', 10);
    const user = new User({
      full_name,
      email,
      role,
      password: defaultPassword
    });
    await user.save();
    res.json({
      user_id: user._id,
      full_name: user.full_name,
      email: user.email,
      role: user.role,
      created_at: user.created_at
    });
  } catch (err) {
    console.error(err);
    if (err.code === 11000) {
      return res.status(400).send('Email already exists');
    }
    res.status(500).send('Error adding user');
  }
});

app.get('/users/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).send('User not found');
    res.json({
      user_id: user._id,
      full_name: user.full_name,
      email: user.email,
      role: user.role
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching user');
  }
});

app.put('/users/me', authenticate, async (req, res) => {
  const { full_name, email, password } = req.body;
  try {
    const updateData = { full_name, email };
    if (password) {
      updateData.password = await bcrypt.hash(password, 10);
    }
    const user = await User.findByIdAndUpdate(
      req.user.id,
      updateData,
      { new: true }
    ).select('-password');
    
    if (!user) return res.status(404).send('User not found');
    res.json({
      user_id: user._id,
      full_name: user.full_name,
      email: user.email,
      role: user.role
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating user');
  }
});

app.put('/users/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { full_name, email, role } = req.body;
  try {
    const user = await User.findByIdAndUpdate(
      id,
      { full_name, email, role },
      { new: true }
    ).select('-password');
    
    if (!user) return res.status(404).send('User not found');
    res.json({
      user_id: user._id,
      full_name: user.full_name,
      email: user.email,
      role: user.role,
      created_at: user.created_at
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating user');
  }
});

app.delete('/users/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    await User.findByIdAndDelete(id);
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
    const books = await Book.find().sort({ _id: 1 });
    const formattedBooks = books.map(book => ({
      book_id: book._id,
      title: book.title,
      author: book.author,
      published_year: book.published_year,
      isbn: book.isbn,
      copies_available: book.copies_available,
      created_at: book.created_at
    }));
    res.json(formattedBooks);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching books');
  }
});

app.post('/books', authenticate, async (req, res) => {
  const { title, author, published_year, isbn, copies_available } = req.body;
  try {
    const book = new Book({
      title,
      author,
      published_year,
      isbn,
      copies_available: copies_available || 1
    });
    await book.save();
    res.json({
      book_id: book._id,
      title: book.title,
      author: book.author,
      published_year: book.published_year,
      isbn: book.isbn,
      copies_available: book.copies_available,
      created_at: book.created_at
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error adding book');
  }
});

app.put('/books/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { title, author, published_year, isbn, copies_available } = req.body;
  try {
    const book = await Book.findByIdAndUpdate(
      id,
      { title, author, published_year, isbn, copies_available },
      { new: true }
    );
    if (!book) return res.status(404).send('Book not found');
    res.json({
      book_id: book._id,
      title: book.title,
      author: book.author,
      published_year: book.published_year,
      isbn: book.isbn,
      copies_available: book.copies_available,
      created_at: book.created_at
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating book');
  }
});

app.delete('/books/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    await Book.findByIdAndDelete(id);
    res.send('Book deleted');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting book');
  }
});

app.post('/bulk-books', authenticate, async (req, res) => {
  const books = req.body.books;
  if (!Array.isArray(books)) {
    return res.status(400).send('Books must be an array');
  }
  try {
    await Book.insertMany(books);
    res.json({ message: 'Books added successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error adding books');
  }
});

// ===============================
// BORROW RECORDS ROUTES
// ===============================
app.get('/borrow_records', authenticate, async (req, res) => {
  try {
    const records = await BorrowRecord.find()
      .populate('book_id', 'title')
      .sort({ _id: 1 });
    
    const formattedRecords = records.map(record => ({
      record_id: record._id,
      user_name: record.user_name,
      title: record.book_id?.title || 'Unknown',
      borrow_date: record.borrow_date,
      due_date: record.due_date,
      return_date: record.return_date,
      status: record.status
    }));
    res.json(formattedRecords);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching borrow records');
  }
});

app.post('/borrow_records', authenticate, async (req, res) => {
  const { user_name, book_id, due_date } = req.body;
  try {
    const record = new BorrowRecord({
      user_name,
      book_id,
      due_date
    });
    await record.save();
    res.json({
      record_id: record._id,
      user_name: record.user_name,
      book_id: record.book_id,
      borrow_date: record.borrow_date,
      due_date: record.due_date,
      status: record.status
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error creating borrow record');
  }
});

app.put('/borrow_records/:id/return', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const record = await BorrowRecord.findByIdAndUpdate(
      id,
      { return_date: new Date(), status: 'returned' },
      { new: true }
    );
    if (!record) return res.status(404).send('Record not found');
    res.json({
      record_id: record._id,
      user_name: record.user_name,
      book_id: record.book_id,
      borrow_date: record.borrow_date,
      due_date: record.due_date,
      return_date: record.return_date,
      status: record.status
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating borrow record');
  }
});

app.delete('/borrow_records/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    await BorrowRecord.findByIdAndDelete(id);
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
    const mostBorrowed = await BorrowRecord.aggregate([
      {
        $group: {
          _id: '$book_id',
          borrow_count: { $sum: 1 }
        }
      },
      {
        $lookup: {
          from: 'books',
          localField: '_id',
          foreignField: '_id',
          as: 'book'
        }
      },
      { $unwind: '$book' },
      {
        $project: {
          title: '$book.title',
          borrow_count: 1
        }
      },
      { $sort: { borrow_count: -1 } },
      { $limit: 10 }
    ]);
    res.json(mostBorrowed);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching most borrowed books');
  }
});

app.get('/reports/active-users', authenticate, async (req, res) => {
  try {
    const activeUsers = await BorrowRecord.aggregate([
      {
        $group: {
          _id: '$user_name',
          borrow_count: { $sum: 1 }
        }
      },
      {
        $project: {
          user_name: '$_id',
          borrow_count: 1,
          _id: 0
        }
      },
      { $sort: { borrow_count: -1 } },
      { $limit: 10 }
    ]);
    res.json(activeUsers);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching active users');
  }
});

app.get('/reports/overdue', async (req, res) => {
  try {
    const overdueRecords = await BorrowRecord.find({
      return_date: null,
      due_date: { $lt: new Date() }
    }).populate('book_id', 'title');
    
    const formattedOverdue = overdueRecords.map(record => {
      const overdueDays = Math.floor(
        (new Date() - new Date(record.due_date)) / (1000 * 60 * 60 * 24)
      );
      return {
        user_name: record.user_name,
        title: record.book_id?.title || 'Unknown',
        due_date: record.due_date,
        overdue_days: overdueDays,
        fine: overdueDays * 1
      };
    });
    res.json(formattedOverdue);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching overdue books');
  }
});

// ===============================
// STATS ROUTES
// ===============================
app.get('/stats/previous', authenticate, async (req, res) => {
  try {
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    yesterday.setHours(0, 0, 0, 0);
    
    const stats = await StatsHistory.findOne({
      date: { $gte: yesterday }
    }).sort({ date: -1 });
    
    if (!stats) {
      return res.json({ 
        totalBooks: 0, 
        totalUsers: 0, 
        activeBorrows: 0, 
        overdueBooks: 0 
      });
    }
    
    res.json({
      totalBooks: stats.total_books,
      totalUsers: stats.total_users,
      activeBorrows: stats.active_borrows,
      overdueBooks: stats.overdue_books
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error fetching previous stats');
  }
});

app.post('/stats/insert-daily', authenticate, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const totalBooks = await Book.countDocuments();
    const totalUsers = await User.countDocuments();
    const activeBorrows = await BorrowRecord.countDocuments({ return_date: null });
    const overdueBooks = await BorrowRecord.countDocuments({
      return_date: null,
      due_date: { $lt: new Date() }
    });
    
    await StatsHistory.findOneAndUpdate(
      { date: today },
      {
        total_books: totalBooks,
        total_users: totalUsers,
        active_borrows: activeBorrows,
        overdue_books: overdueBooks
      },
      { upsert: true, new: true }
    );
    
    res.json({ message: 'Daily stats inserted' });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error inserting stats');
  }
});

// ===============================
// START SERVER
// ===============================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});