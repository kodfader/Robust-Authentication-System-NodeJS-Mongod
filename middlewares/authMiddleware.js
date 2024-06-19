// middleware/authMiddleware.js
const asyncHandler = require('./asyncHandler');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');

// Middleware to protect routes
const protect = asyncHandler(async (req, res, next) => {
    let token;

    if (req.session && req.session.token) {
        token = req.session.token;
        try {
            // Verify token
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            const user = await User.findOne({ _id: decoded.id, token });

            if (!user) {
                res.status(401);
                throw new Error('Not authorized, token invalid');
            }

            req.user = user;
            next();
        } catch (error) {
            res.status(401);
            throw new Error('Not authorized, token failed');
        }
    } else {
        res.status(401);
        throw new Error('Not authorized, no token');
    }
});

module.exports = { protect };
