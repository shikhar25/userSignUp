const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const validateOTP = require('../middlewares/validateOTP');

router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.post('/verify-otp', validateOTP, authController.verifyOtp);
router.post('/refresh-token', authController.refreshToken);

module.exports = router;
