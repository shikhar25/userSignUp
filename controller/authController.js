const authService = require('../services/authService');
const jwt = require('jsonwebtoken');
const { generateAccessToken } = require('../utils/jwt');

exports.signup = async (req, res) => {
    try {
        await authService.signup(req.body);
        res.json({ message: 'User registered' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

exports.login = async (req, res) => {
    try {
        const result = await authService.login(req.body.email, req.body.password);
        if (result.error) return res.status(400).json({ error: result.error });
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

exports.verifyOtp = async (req, res) => {
    try {
        const result = await authService.verifyOtp(req.body.email, req.body.otp);
        if (result.error) return res.status(400).json({ error: result.error });
        res.json({ message: 'Login successful', user: result.user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

exports.refreshToken = async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ error: 'Refresh token required' });
  
    try {
      const user = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
      const accessToken = generateAccessToken(user);
      res.json({ accessToken });
    } catch {
      res.status(403).json({ error: 'Invalid refresh token' });
    }
  };