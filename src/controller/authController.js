const jwt = require('jsonwebtoken');
const Users = require('../model/Users');
const bcrypt = require('bcryptjs');
const { OAuth2Client } = require('google-auth-library');
const { validationResult } = require('express-validator');

const secret = process.env.JWT_SECRET;
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const authController = {
    //---------------- LOGIN ----------------
    login: async (req, res) => {
        try {
            const errors=validationResult(request);
            if(!errors.isEmpty()){
                return response.status(401).json({ errors: errors.array() });
            }
            const { username, password } = req.body;
            const user = await Users.findOne({ email: username });

            if (!user) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            const token = jwt.sign({
                id: user._id,
                name: user.name,
                email: user.email
            }, secret, { expiresIn: '1h' });

            res.cookie('jwtToken', token, {
                httpOnly: true,
                secure: false, // set to true in production with HTTPS
                sameSite: 'lax'
            });

            res.json({ user: user, message: 'User authenticated' });

        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    },

    //---------------- LOGOUT ----------------
    logout: (req, res) => {
        res.clearCookie('jwtToken');
        res.status(200).json({ message: 'User is logged out' });
    },

    //---------------- IS USER LOGGED IN ----------------
    isUserLoggedIn: (req, res) => {
        const token = req.cookies.jwtToken;
        if (!token) {
            return res.status(401).json({ message: 'User is not logged in' });
        }

        jwt.verify(token, secret, (err, user) => {
            if (err) {
                return res.status(401).json({ message: 'Invalid token' });
            } else {
                return res.status(200).json({ user: user, message: 'User is logged in' });
            }
        });
    },

    //---------------- REGISTER ----------------
    register: async (req, res) => {
        try {
            const { username, password, name } = req.body;
            const existingUser = await Users.findOne({ email: username });

            if (existingUser) {
                return res.status(401).json({ message: 'User already exists' });
            }

            const hashedPassword = await bcrypt.hash(password, 10);

            const user = new Users({
                email: username,
                password: hashedPassword,
                name: name
            });

            await user.save();
            res.status(201).json({ message: 'User registered successfully' });

        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Internal server error' });
        }
    },

    //---------------- GOOGLE AUTH ----------------
    googleAuth: async (req, res) => {
        try {
            const { idToken } = req.body;

            const ticket = await googleClient.verifyIdToken({
                idToken,
                audience: process.env.GOOGLE_CLIENT_ID
            });

            const payload = ticket.getPayload();
            const { sub: googleId, name, email } = payload;

            let user = await Users.findOne({ email: email });

            if (!user) {
                user = new Users({
                    email: email,
                    name: name,
                    isGoogleUser: true,
                    googleId: googleId
                });
                await user.save();
            }

            const token = jwt.sign({
                id: user._id,
                name: user.name,
                email: user.email
            }, secret, { expiresIn: '1h' });

            res.cookie('jwtToken', token, {
                httpOnly: true,
                secure: false, // set to true in production with HTTPS
                sameSite: 'lax'
            });

            res.json({ user: user, message: 'User authenticated' });

        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Internal server error' });
        }
    },
};

module.exports = authController;
