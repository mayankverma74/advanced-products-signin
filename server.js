require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const axios = require('axios');
const path = require('path');
const fetch = require('node-fetch');
const User = require('./models/User');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.use(cors());

// Request logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Serve static files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Store OTPs temporarily (still in memory as they are temporary)
const otps = new Map();

// Generate OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Function to send OTP via 2Factor API
async function sendOTPvia2Factor(phone, otp) {
    try {
        const apiKey = process.env.TWO_FACTOR_API_KEY;
        if (!apiKey) {
            throw new Error('2Factor API key not configured');
        }

        console.log('Sending OTP using 2Factor API');
        const url = `https://2factor.in/API/V1/${apiKey}/SMS/${phone}/${otp}/OTP1`;
        
        const response = await axios.get(url);
        console.log('2Factor API Response:', response.data);
        
        if (response.data.Status !== 'Success') {
            throw new Error('Failed to send OTP via 2Factor');
        }
        
        return response.data;
    } catch (error) {
        console.error('Error sending OTP:', error.message);
        throw new Error('Failed to send OTP: ' + error.message);
    }
}

// MongoDB Connection Setup
async function connectToMongoDB() {
    const maxRetries = 5;
    let currentRetry = 0;

    while (currentRetry < maxRetries) {
        try {
            console.log('Connecting to MongoDB Atlas...');
            await mongoose.connect(process.env.MONGODB_URI, {
                useNewUrlParser: true,
                useUnifiedTopology: true,
                serverSelectionTimeoutMS: 5000, // Timeout after 5 seconds
                socketTimeoutMS: 45000, // Close sockets after 45 seconds
            });
            console.log('Connected to MongoDB Atlas!');
            return;
        } catch (error) {
            currentRetry++;
            console.error(`MongoDB connection attempt ${currentRetry} failed:`, error.message);
            
            if (currentRetry === maxRetries) {
                console.error('Failed to connect to MongoDB after maximum retries');
                // Start server even if MongoDB fails
                break;
            }
            
            // Wait for 2 seconds before retrying
            await new Promise(resolve => setTimeout(resolve, 2000));
        }
    }
}

// Signup route - Step 1: Send OTP
app.post('/api/signup/send-otp', async (req, res) => {
    try {
        console.log('Received signup request:', req.body);
        const { fullName, phone, password } = req.body;

        // Validate input
        if (!fullName || !phone || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (!/^[0-9]{10}$/.test(phone)) {
            return res.status(400).json({ error: 'Invalid phone number' });
        }

        if (fullName.trim().split(/\s+/).length < 2) {
            return res.status(400).json({ error: 'Please enter your full name (first and last name)' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ phone });
        if (existingUser) {
            return res.status(400).json({ error: 'Phone number already registered' });
        }

        // Generate OTP
        const otp = generateOTP();
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Store OTP data
        otps.set(phone, {
            otp,
            fullName,
            hashedPassword,
            timestamp: Date.now()
        });

        // Send real OTP via 2Factor
        await sendOTPvia2Factor(phone, otp);
        console.log(`OTP sent to ${phone}`);
        res.json({ message: 'OTP sent successfully' });

    } catch (err) {
        console.error('Error in send-otp:', err);
        res.status(500).json({ error: err.message || 'Failed to send OTP' });
    }
});

// Signup route - Step 2: Verify OTP
app.post('/api/signup/verify-otp', async (req, res) => {
    try {
        console.log('Received OTP verification request:', req.body);
        const { phone, otp } = req.body;

        if (!phone || !otp) {
            return res.status(400).json({ error: 'Phone and OTP are required' });
        }

        const storedData = otps.get(phone);
        console.log('Stored OTP data:', { phone, storedOTP: storedData?.otp, receivedOTP: otp });
        
        if (!storedData) {
            return res.status(400).json({ error: 'No OTP request found. Please request a new OTP.' });
        }

        // Check OTP expiration (5 minutes)
        const timeDiff = Date.now() - storedData.timestamp;
        console.log('OTP time difference:', timeDiff, 'ms');
        
        if (timeDiff > 5 * 60 * 1000) {
            otps.delete(phone);
            return res.status(400).json({ error: 'OTP expired. Please request a new OTP.' });
        }

        // Convert both OTPs to strings and trim any whitespace
        const storedOTP = storedData.otp.toString().trim();
        const receivedOTP = otp.toString().trim();
        
        console.log('OTP comparison:', {
            stored: storedOTP,
            received: receivedOTP,
            match: storedOTP === receivedOTP
        });

        if (storedOTP !== receivedOTP) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        // Create new user
        const user = new User({
            fullName: storedData.fullName,
            phone: phone,
            password: storedData.hashedPassword
        });

        await user.save();
        console.log('New user created:', { phone, fullName: storedData.fullName });

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Remove OTP data
        otps.delete(phone);

        res.json({
            message: 'Signup successful',
            token,
            user: {
                id: user._id,
                fullName: user.fullName,
                phone: user.phone
            }
        });

    } catch (err) {
        console.error('Error in verify-otp:', err);
        res.status(500).json({ error: err.message || 'Failed to verify OTP' });
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { phone, password } = req.body;

        // Validate input
        if (!phone || !password) {
            return res.status(400).json({ error: 'Phone and password are required' });
        }

        // Find user
        const user = await User.findOne({ phone });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Send response
        res.json({
            token,
            user: {
                id: user._id,
                fullName: user.fullName,
                phone: user.phone
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get all users (for testing)
app.get('/api/users', async (req, res) => {
    try {
        const users = await User.find({}, '-password');
        res.json(users);
    } catch (err) {
        console.error('Error fetching users:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get specific user
app.get('/api/users/:phone', async (req, res) => {
    try {
        const user = await User.findOne({ phone: req.params.phone }, '-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(user);
    } catch (err) {
        console.error('Error fetching user:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

// Reset Password Routes
app.post('/api/reset-password/send-otp', async (req, res) => {
    try {
        const { phone } = req.body;
        console.log('Received reset password request for phone:', phone);

        // Check if phone exists in database
        const user = await User.findOne({ phone });
        if (!user) {
            return res.status(404).json({ error: 'Phone number not registered' });
        }

        // Generate and store OTP
        const otp = generateOTP();
        const otpExpiry = new Date(Date.now() + 5 * 60000); // 5 minutes

        user.resetPasswordOtp = otp;
        user.resetPasswordOtpExpiry = otpExpiry;
        await user.save();

        // Send OTP via 2Factor
        const otpResponse = await sendOTPvia2Factor(phone, otp);
        console.log('Reset password OTP sent successfully');
        res.json({ message: 'OTP sent successfully' });
    } catch (error) {
        console.error('Reset password send OTP error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/reset-password/resend-otp', async (req, res) => {
    try {
        const { phone } = req.body;
        console.log('Received reset password resend request for phone:', phone);

        const user = await User.findOne({ phone });
        if (!user) {
            return res.status(404).json({ error: 'Phone number not registered' });
        }

        // Generate and store new OTP
        const otp = generateOTP();
        const otpExpiry = new Date(Date.now() + 5 * 60000); // 5 minutes

        user.resetPasswordOtp = otp;
        user.resetPasswordOtpExpiry = otpExpiry;
        await user.save();

        // Send OTP via 2Factor
        const otpResponse = await sendOTPvia2Factor(phone, otp);
        console.log('Reset password OTP resent successfully');
        res.json({ message: 'OTP resent successfully' });
    } catch (error) {
        console.error('Reset password resend OTP error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/reset-password/verify-otp', async (req, res) => {
    try {
        const { phone, otp } = req.body;

        const user = await User.findOne({ 
            phone,
            resetPasswordOtp: otp,
            resetPasswordOtpExpiry: { $gt: new Date() }
        });

        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        res.json({ message: 'OTP verified successfully' });
    } catch (error) {
        console.error('Reset password verify OTP error:', error);
        res.status(500).json({ error: 'Failed to verify OTP' });
    }
});

app.post('/api/reset-password/update', async (req, res) => {
    try {
        const { phone, newPassword } = req.body;
        console.log('Received password update request for phone:', phone);

        // Find user and verify OTP expiry
        const user = await User.findOne({ phone });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (!user.resetPasswordOtp || !user.resetPasswordOtpExpiry) {
            return res.status(400).json({ error: 'Please verify OTP first' });
        }

        if (new Date() > user.resetPasswordOtpExpiry) {
            return res.status(400).json({ error: 'OTP has expired. Please request a new one' });
        }

        // Hash new password and update
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetPasswordOtp = null;
        user.resetPasswordOtpExpiry = null;
        await user.save();

        console.log('Password updated successfully');
        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Password update error:', error);
        res.status(500).json({ error: 'Failed to update password: ' + error.message });
    }
});

// Connect to MongoDB and start server
connectToMongoDB().then(() => {
    app.listen(port, '0.0.0.0', () => {
        console.log(`Server is running on http://0.0.0.0:${port}`);
        console.log(`Access from mobile: http://192.168.146.38:${port}`);
    });
}).catch(error => {
    console.error('Failed to start server:', error);
});
