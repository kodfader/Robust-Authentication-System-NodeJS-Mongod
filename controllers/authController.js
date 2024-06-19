// controllers/authController.js
const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');
const generateToken = require('../helpers/generateToken');
const { registerValidation, loginValidation } = require('../validations/authValidation');

// Register a new user
const registerUser = asyncHandler(async (req, res) => {
    const { error } = registerValidation(req.body);
    if (error) {
        res.status(400);
        throw new Error(error.details[0].message);
    }

    const { username, email, password } = req.body;
    const userExists = await User.findOne({ email });

    if (userExists) {
        res.status(400);
        throw new Error('User already exists');
    }

    const user = await User.create({ username, email, password });

    if (user) {
        res.status(201).json({
            _id: user._id,
            username: user.username,
            email: user.email,
            message: 'User registered successfully. Please login to continue.'
        });
    } else {
        res.status(400);
        throw new Error('Invalid user data');
    }
});

// Login an existing user
const loginUser = asyncHandler(async (req, res) => {
    const { error } = loginValidation(req.body);
    if (error) {
        res.status(400);
        throw new Error(error.details[0].message);
    }

    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (user && (await user.matchPassword(password))) {
        if (user.token) {
            res.status(400);
            throw new Error('User already logged in');
        }
        const token = generateToken(user._id);
        user.token = token;
        await user.save();
        req.session.token = token;
        res.json({
            _id: user._id,
            username: user.username,
            email: user.email,
            token: req.session.token,
        });
    } else {
        res.status(401);
        throw new Error('Invalid email or password');
    }
});

// Logout the user
const logoutUser = asyncHandler(async (req, res) => {
    if (req.session) {
        const token = req.session.token;
        const user = await User.findOne({ token });
        if (user) {
            user.token = null;
            await user.save();
        }
        req.session.destroy(err => {
            if (err) {
                res.status(400).send('Unable to log out');
            } else {
                res.redirect('/login');
            }
        });
    } else {
        res.end();
    }
});

module.exports = { registerUser, loginUser, logoutUser };
