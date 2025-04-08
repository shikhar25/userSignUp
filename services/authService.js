const bcrypt = require('bcrypt');
const { findUserByEmail, createUser, updateFailedAttempts, resetFailedAttempts, updateOTP, verifyOTP } = require('../models/userModel');
const { generateOTP } = require('../utils/otpUtil');
const { sendOTP } = require('../utils/email');
const { generateAccessToken } = require('../utils/jwt');

const MAX_ATTEMPTS = 5;
const LOCK_DURATION = 15 * 60 * 1000; // 15 minutes

exports.signup = async ({ name, email, password }) => {
  const hashed = await bcrypt.hash(password, 10);
  await createUser({ name, email, password: hashed });
};

exports.login = async (email, password) => {
  const user = await findUserByEmail(email);
  if (!user) return { error: 'User not found' };

  const now = new Date();

  if (user.lock_until && now < user.lock_until) {
    return { error: 'Account locked. Try later.' };
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    let attempts = (user.failed_attempts || 0) + 1;
    const lockUntil = attempts >= MAX_ATTEMPTS ? new Date(now.getTime() + LOCK_DURATION) : null;
    await updateFailedAttempts(email, attempts, lockUntil);
    return { error: attempts >= MAX_ATTEMPTS ? 'Account locked for 15 mins' : 'Invalid password' };
  }

  await resetFailedAttempts(email);

  const otp = generateOTP();
  await updateOTP(email, otp);

  // In real app, send OTP via email/SMS
  return { message: 'OTP sent', otp };
};

exports.verifyOtp = async (email, otp) => {
  const user = await verifyOTP(email, otp);
  return user ? { success: true, user } : { error: 'Invalid OTP' };
};

// inside login()
await sendOTP(email, otp); // send email
return { message: 'OTP sent to email' };

// inside verifyOtp()
if (user) {
  const accessToken = generateAccessToken(user);
//   const refreshToken = generateRefreshToken(user);
  return { success: true, accessToken, refreshToken };
}