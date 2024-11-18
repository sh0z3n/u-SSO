const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true
}));


app.use('/api/', limiter);
app.get('/', (req, res) => {
    res.json({ sso: 'is up!' });
    res.redirect('/api/');
    });

// Routes
app.use('/.well-known/openid-configuration', require('./routes/discovery.routes'));
app.use('/sso', require('./routes/sso.routes'));
app.use('/auth', require('./routes/auth.routes'));
app.use('/admin/sso', require('./routes/admin.sso.routes'));

// Test routes
app.get('/api/test/public', (req, res) => {
  res.json({ message: 'Public endpoint working!' });
});

app.get('/api/test/protected', authenticateToken, (req, res) => {
  console.log(authenticateToken);
  res.json({ message: 'Protected endpoint working!', user: req.user });
});

// Error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;