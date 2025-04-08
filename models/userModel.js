const db = require('../config/db');

exports.findUserByEmail = async (email) => {
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    return rows[0];
};

exports.createUser = async (user) => {
    const { name, email, password } = user;
    await db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, password]);
};

exports.updateFailedAttempts = async (email, attempts, lockUntil) => {
    await db.query('UPDATE users SET failed_attempts = ?, lock_until = ? WHERE email = ?', [attempts, lockUntil, email]);
};

exports.resetFailedAttempts = async (email) => {
    await db.query('UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE email = ?', [email]);
};

exports.updateOTP = async (email, otp) => {
    await db.query('UPDATE users SET otp = ? WHERE email = ?', [otp, email]);
};

exports.verifyOTP = async (email, otp) => {
    const [rows] = await db.query('SELECT * FROM users WHERE email = ? AND otp = ?', [email, otp]);
    return rows[0];
};
