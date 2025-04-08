const express = require('express');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'yourpassword',
  database: 'yourdb'
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'yoursecret';

// Send OTP utility (console mock)
async function sendOTP(email, otp) {
  console.log(`Sending OTP ${otp} to ${email}`);
  // Configure nodemailer here if you want real emails
}

// 1. Signup
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await pool.query(`
      INSERT INTO users (email, password, failed_attempts, lock_until)
      VALUES (?, ?, 0, NULL)
    `, [email, hashedPassword]);

    res.json({ message: 'Signup successful' });
  } catch (err) {
    res.status(400).json({ error: 'User already exists or DB error' });
  }
});

// 2. Login: Password Check & OTP Generation
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const [[user]] = await pool.query(`SELECT * FROM users WHERE email = ?`, [email]);
  if (!user) return res.status(400).json({ error: 'User not found' });

  const now = new Date();
  if (user.lock_until && new Date(user.lock_until) > now) {
    return res.status(403).json({ error: 'Account is locked. Try again later.' });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    const attempts = (user.failed_attempts || 0) + 1;
    const lockUntil = attempts >= 5 ? new Date(now.getTime() + 15 * 60000) : null;

    await pool.query(
      `UPDATE users SET failed_attempts = ?, lock_until = ? WHERE email = ?`,
      [attempts, lockUntil, email]
    );

    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Password is valid → reset attempts & generate OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpExpiry = new Date(now.getTime() + 10 * 60000); // 10 minutes from now

  await pool.query(
    `UPDATE users SET failed_attempts = 0, lock_until = NULL, otp = ?, otp_expires = ? WHERE email = ?`,
    [otp, otpExpiry, email]
  );

  await sendOTP(email, otp);
  res.json({ message: 'OTP sent to email' });
});

// 3. OTP Verification & JWT Token Generation
app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  const [[user]] = await pool.query(`SELECT * FROM users WHERE email = ?`, [email]);
  if (!user || user.otp !== otp || new Date(user.otp_expires) < new Date()) {
    return res.status(400).json({ error: 'Invalid or expired OTP' });
  }

  // OTP is valid → clear it and generate JWT
  await pool.query(
    `UPDATE users SET otp = NULL, otp_expires = NULL WHERE email = ?`,
    [email]
  );

  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: '1h'
  });

  res.json({ message: 'Login successful', token });
});

// Optional: Protected route example
app.get('/protected', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ message: 'Access granted', user: decoded });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(3000, () => console.log('Server running on port 3000'));
