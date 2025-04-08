module.exports = (req, res, next) => {
    const { otp } = req.body;
    if (!otp) return res.status(400).json({ error: 'OTP is required' });
    next();
};
