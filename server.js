require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const path = require('path');
const axios = require('axios');
const cron = require('node-cron');
const User = require('./models/User');
const Transaction = require('./models/Transaction');
const TWO_FACTOR_API_KEY = 'd9c5e45b-061d-11f0-8b17-0200cd936042';
const Admin = require('./models/Admin');
const fetch = require('node-fetch');

const app = express();
const port = process.env.PORT || 3000;

// Store OTPs temporarily (in production, use Redis or similar)
const otpStore = new Map();
const otpMap = new Map();
// Middleware
app.use(express.json());
app.use(cors());

// MongoDB Connection
const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 30000, // Increased timeout to 30 seconds
            retryWrites: true,
            w: 'majority'
        });
        console.log('Connected to MongoDB Atlas successfully');
        return true;
    } catch (err) {
        console.error('MongoDB Atlas connection error:', err);
        return false;
    }
};

// Handle MongoDB connection events
mongoose.connection.on('connected', () => {
    console.log('Mongoose connected to MongoDB Atlas');
});

mongoose.connection.on('error', (err) => {
    console.error('Mongoose connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('Mongoose disconnected from MongoDB Atlas');
});

process.on('SIGINT', async () => {
    try {
        await mongoose.connection.close();
        console.log('MongoDB Atlas connection closed through app termination');
        process.exit(0);
    } catch (err) {
        console.error('Error closing MongoDB connection:', err);
        process.exit(1);
    }
});

// Generate OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Send OTP (mock function - replace with actual SMS service)
function sendOTP(phone, otp) {
    console.log(`Sending OTP ${otp} to ${phone}`);
    return Promise.resolve();
}

// Helper function to send OTP via 2Factor.in
async function sendOTPvia2Factor(phone, otp) {
    try {
        const response = await axios.get(`https://2factor.in/API/V1/${TWO_FACTOR_API_KEY}/SMS/${phone}/${otp}`);
        return response.data.Status === 'Success';
    } catch (error) {
        console.error('Error sending OTP via 2Factor:', error);
        return false;
    }
}

// API Routes
app.post('/api/send-otp', async (req, res) => {
    try {
        const { phone } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ phone });
        if (existingUser) {
            return res.status(400).json({ error: 'Phone number already registered' });
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        // Store OTP with expiry
        otpStore.set(phone, {
            otp,
            expiry: Date.now() + 5 * 60 * 1000, // 5 minutes expiry
            attempts: 0
        });

        // Send OTP via 2Factor.in
        const sent = await sendOTPvia2Factor(phone, otp);
        if (!sent) {
            throw new Error('Failed to send OTP');
        }

        console.log(`Signup OTP sent to ${phone} successfully`);
        res.json({ message: 'OTP sent successfully' });
    } catch (error) {
        console.error('Error in send OTP:', error);
        res.status(500).json({ error: error.message || 'Internal server error' });
    }
});

app.post('/api/verify-otp', async (req, res) => {
    try {
        const { fullName, phone, password, otp, referralCode } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ phone });
        if (existingUser) {
            return res.status(400).json({ error: 'Phone number already registered' });
        }

        // Verify OTP
        const otpData = otpStore.get(phone);
        if (!otpData) {
            return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
        }

        if (otpData.expiry < Date.now()) {
            otpStore.delete(phone);
            return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
        }

        if (otpData.attempts >= 3) {
            otpStore.delete(phone);
            return res.status(400).json({ error: 'Too many attempts. Please request a new OTP.' });
        }

        if (otpData.otp !== otp) {
            otpData.attempts++;
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        // If OTP is valid, proceed with user creation
        const hashedPassword = await bcrypt.hash(password, 10);

        // Check referral code if provided
        let referrer = null;
        if (referralCode) {
            referrer = await User.findOne({ referralCode });
            if (!referrer) {
                return res.status(400).json({ error: 'Invalid referral code' });
            }
        }

        // Create new user
        const newUser = new User({
            fullName,
            phone,
            password: hashedPassword,
            referredBy: referrer ? referrer._id : null,
            points: referralCode ? 50 : 0 // Give 50 points to new user if they used a referral code
        });

        await newUser.save();

        // Update referrer if exists
        if (referrer) {
            // Add 100 points to referrer
            referrer.points += 100;
            referrer.referralEarnings += 100;
            referrer.referrals.push(newUser._id);
            await referrer.save();

            // Create transaction records for both users
            await Transaction.create({
                userId: newUser._id,
                type: 'referral_bonus',
                amount: 50,
                status: 'completed',
                description: 'Referral signup bonus'
            });

            await Transaction.create({
                userId: referrer._id,
                type: 'referral_bonus',
                amount: 100,
                status: 'completed',
                description: 'Referral reward'
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: newUser._id },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Account created successfully',
            token,
            referralBonus: referralCode ? 50 : 0
        });

    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Failed to create account' });
    }
});

app.post('/api/claim-points', authenticateToken, async (req, res) => {
    const userId = req.user.userId; // Get user ID from token
    const currentTime = new Date();

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check if the user can claim points
        if (user.lastClaimTime) {
            const lastClaimTime = new Date(user.lastClaimTime);
            const oneHour = 60 * 60 * 1000; // 1 hour in milliseconds

            if (currentTime - lastClaimTime < oneHour) {
                return res.status(403).json({ error: 'You can only claim points once every hour.' });
            }
        }

        // Update user's points and last claim time
        user.points += 2; // Add 2 points
        user.lastClaimTime = currentTime; // Update last claim time
        await user.save();

        res.json({ message: 'Points claimed successfully!', newPoints: user.points });
    } catch (error) {
        console.error('Error claiming points:', error);
        res.status(500).json({ error: 'An error occurred while claiming points.' });
    }
});
// Unified login endpoint
app.post('/api/login', async (req, res) => {
    try {
        console.log('Login attempt:', req.body);
        const { phone, password } = req.body;

        if (!phone || !password) {
            console.log('Missing fields');
            return res.status(400).json({ 
                error: 'Phone and password are required',
                type: 'MISSING_FIELDS'
            });
        }

        // Find user by phone number
        const user = await User.findOne({ phone });
        console.log('Found user:', { 
            _id: user?._id,
            phone: user?.phone,
            userType: user?.userType,
            fullName: user?.fullName,
            hasPassword: !!user?.password
        });

        if (!user) {
            console.log('User not found');
            return res.status(401).json({ 
                error: 'Invalid phone number or password',
                type: 'INVALID_CREDENTIALS'
            });
        }

        // Log password comparison attempt
        console.log('Attempting password comparison:', {
            userId: user._id,
            hasStoredPassword: !!user.password
        });

        // Compare password using bcrypt
        const isPasswordValid = await bcrypt.compare(password, user.password);
        console.log('Password validation result:', { 
            isValid: isPasswordValid,
            userId: user._id
        });

        if (!isPasswordValid) {
            console.log('Invalid password');
            return res.status(401).json({ 
                error: 'Invalid phone number or password',
                type: 'INVALID_CREDENTIALS'
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, userType: user.userType },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        console.log('Login successful:', {
            userId: user._id,
            phone: user.phone,
            userType: user.userType
        });

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                fullName: user.fullName,
                phone: user.phone,
                userType: user.userType,
                walletBalance: user.walletBalance,
                points: user.points
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Failed to login' });
    }
});

// Forgot password - send OTP
app.post('/api/forgot-password/send-otp', async (req, res) => {
    try {
        const { phone } = req.body;
        
        // Check if user exists
        const user = await User.findOne({ phone });
        if (!user) {
            return res.status(404).json({ error: 'Phone number is not registered' });
        }

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        
        // Store OTP with expiry
        otpStore.set(phone, {
            otp,
            expiry: Date.now() + 5 * 60 * 1000, // 5 minutes expiry
            attempts: 0
        });

        // Send OTP via 2Factor.in
        const sent = await sendOTPvia2Factor(phone, otp);
        if (!sent) {
            throw new Error('Failed to send OTP');
        }

        console.log(`OTP sent to ${phone} successfully`);
        res.json({ message: 'OTP sent successfully on WhatsApp' });
    } catch (error) {
        console.error('Error in forgot password send OTP:', error);
        res.status(500).json({ error: error.message || 'Internal server error' });
    }
});

// Forgot password - verify OTP
app.post('/api/forgot-password/verify-otp', async (req, res) => {
    try {
        const { phone, otp } = req.body;
        
        const otpData = otpStore.get(phone);
        if (!otpData) {
            return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
        }

        if (otpData.expiry < Date.now()) {
            otpStore.delete(phone);
            return res.status(400).json({ error: 'OTP expired. Please request a new one.' });
        }

        if (otpData.attempts >= 3) {
            otpStore.delete(phone);
            return res.status(400).json({ error: 'Too many attempts. Please request a new OTP.' });
        }

        if (otpData.otp !== otp) {
            otpData.attempts++;
            return res.status(400).json({ error: 'Invalid OTP' });
        }

        // OTP verified successfully
        otpStore.delete(phone);
        res.json({ message: 'OTP verified successfully' });
    } catch (error) {
        console.error('Error in forgot password verify OTP:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Forgot password - reset password
app.post('/api/forgot-password/reset', async (req, res) => {
    try {
        const { phone, newPassword } = req.body;

        // Validate password
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }

        // Find user
        const user = await User.findOne({ phone });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Log the current state
        console.log('Before password change:', {
            userId: user._id,
            phone: user.phone,
            hasPassword: !!user.password
        });

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        
        // Update user's password with the hashed version
        user.password = hashedPassword;
        await user.save();

        // Log the password update
        console.log('Password updated for user:', {
            userId: user._id,
            phone: user.phone,
            passwordUpdated: true,
            hasNewPassword: !!user.password
        });

        // Verify the password was updated correctly
        const updatedUser = await User.findOne({ phone });
        const isPasswordValid = await bcrypt.compare(newPassword, updatedUser.password);
        console.log('Password verification:', {
            isValid: isPasswordValid,
            userId: updatedUser._id,
            phone: updatedUser.phone
        });

        if (!isPasswordValid) {
            console.error('Password verification failed after update');
            return res.status(500).json({ error: 'Failed to update password correctly' });
        }

        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error in forgot password reset:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        console.error('Auth error:', error);
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// Protected routes
app.get('/api/verify-token', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(401).json({ valid: false, error: 'User not found' });
        }
        res.json({ 
            valid: true, 
            user: {
                userId: user._id,
                userType: user.userType,
                fullName: user.fullName,
                phone: user.phone
            }
        });
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(401).json({ valid: false, error: 'Invalid token' });
    }
});

app.get('/api/user/points', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        console.log('User points debug:', {
            userId: user._id,
            points: user.points,
            activePlans: user.activePlans
        });
        res.json({
            points: user.points || 0,
            activePlans: user.activePlans || []
        });
    } catch (error) {
        console.error('Error fetching user points:', error);
        res.status(500).json({ error: 'Failed to fetch user points' });
    }
});

app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId)
            .select('-password')
            .populate('activePlans');

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Format and validate wallet balance and points
        const walletBalance = Number(user.walletBalance || 0);
        const points = Number(user.points || 0);

        // Include referral information in the response
        const userProfile = {
            ...user.toObject(),
            walletBalance: Number(walletBalance.toFixed(2)), // Ensure 2 decimal places
            points: Math.floor(points), // Ensure whole numbers for points
            referralCode: user.referralCode || `AP${user._id.toString().slice(0, 6).toUpperCase()}`,
            totalReferrals: user.referrals ? user.referrals.length : 0,
            referralEarnings: Number(user.referralEarnings || 0)
        };

        // Log the response for debugging
        console.log('User profile response:', {
            userId: user._id,
            walletBalance: userProfile.walletBalance,
            points: userProfile.points,
            totalReferrals: userProfile.totalReferrals
        });

        res.json({ user: userProfile });
    } catch (error) {
        console.error('Error fetching user profile:', error); 
        res.status(500).json({ error: 'Failed to fetch user profile' });
    }
});

app.get('/api/user', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Error fetching user data' });
    }
});

// Transaction routes
app.post('/api/transactions/deposit', authenticateToken, async (req, res) => {
    try {
        const { amount, utrNumber, userName, phoneNumber } = req.body;
        
        const deposit = new Transaction({
            userId: req.user.userId,
            type: 'deposit',
            amount,
            utrNumber,
            userName,
            phoneNumber,
            status: 'pending'
        });

        await deposit.save();
        res.json({ success: true, deposit });
    } catch (error) {
        console.error('Deposit error:', error);
        res.status(500).json({ error: 'Failed to process deposit. Please try again' });
    }
});

app.post('/api/transactions/withdrawal', authenticateToken, async (req, res) => {
    try {
        const { amount, userName, phoneNumber, paymentMode, paymentDetails } = req.body;
        
        console.log('Withdrawal request received:', {
            userId: req.user.userId,
            amount,
            userName,
            phoneNumber,
            paymentMode,
            paymentDetails
        });

        // Validate required fields
        if (!amount || !userName || !phoneNumber || !paymentMode || !paymentDetails) {
            console.log('Missing required fields:', { amount, userName, phoneNumber, paymentMode, paymentDetails });
            return res.status(400).json({ 
                error: 'All fields are required',
                details: {
                    amount: !amount ? 'Amount is required' : null,
                    userName: !userName ? 'User name is required' : null,
                    phoneNumber: !phoneNumber ? 'Phone number is required' : null,
                    paymentMode: !paymentMode ? 'Payment mode is required' : null,
                    paymentDetails: !paymentDetails ? 'Payment details are required' : null
                }
            });
        }

        // Validate amount
        const withdrawalAmount = Number(amount);
        if (isNaN(withdrawalAmount) || withdrawalAmount < 500) {
            console.log('Invalid amount:', amount);
            return res.status(400).json({ 
                error: 'Invalid withdrawal amount',
                details: 'Minimum withdrawal amount is ₹500'
            });
        }

        // Check user's points balance
        const user = await User.findById(req.user.userId);
        if (!user) {
            console.log('User not found:', req.user.userId);
            return res.status(404).json({ 
                error: 'User not found',
                details: 'User account not found'
            });
        }

        const currentPoints = Number(user.points || 0);
        console.log('User points balance:', {
            userId: user._id,
            currentPoints,
            requestedAmount: withdrawalAmount
        });

        if (currentPoints < withdrawalAmount) {
            return res.status(400).json({ 
                error: 'Insufficient points balance',
                details: `You have ${currentPoints} points but requested ${withdrawalAmount} points`
            });
        }

        // Validate payment details based on payment mode
        let validatedPaymentDetails;
        if (paymentMode === 'bank') {
            const { accountName, accountNumber, ifscCode } = paymentDetails;
            if (!accountName || !accountNumber || !ifscCode) {
                return res.status(400).json({
                    error: 'Invalid bank details',
                    details: 'Please provide all bank account details'
                });
            }
            validatedPaymentDetails = JSON.stringify({
                accountName,
                accountNumber,
                ifscCode
            });
        } else if (paymentMode === 'upi') {
            const { upiId, paymentApp } = paymentDetails;
            if (!upiId) {
                return res.status(400).json({
                    error: 'Invalid UPI details',
                    details: 'Please provide a valid UPI ID or phone number'
                });
            }

            // Validate UPI ID format
            const upiRegex = /^[a-zA-Z0-9.\-_]{2,49}@[a-zA-Z._]{2,49}$/;
            const phoneRegex = /^[0-9]{10}$/;
            
            if (!upiRegex.test(upiId) && !phoneRegex.test(upiId)) {
                return res.status(400).json({
                    error: 'Invalid UPI ID format',
                    details: 'Please enter a valid UPI ID (e.g., username@upi) or 10-digit phone number'
                });
            }

            validatedPaymentDetails = JSON.stringify({
                upiId,
                paymentApp
            });
        } else {
            return res.status(400).json({
                error: 'Invalid payment mode',
                details: 'Please select a valid payment method'
            });
        }

        // Create withdrawal transaction
        const withdrawal = new Transaction({
            userId: req.user.userId,
            type: 'withdrawal',
            amount: withdrawalAmount,
            userName,
            phoneNumber,
            paymentMode: paymentMode.toLowerCase(), // Convert to lowercase to match enum
            paymentDetails: validatedPaymentDetails, // Now it's a string
            status: 'pending',
            description: `Withdrawal request via ${paymentMode}`
        });

        // Save the transaction without updating points
        await withdrawal.save();

        console.log('Withdrawal request created successfully:', {
            transactionId: withdrawal._id,
            userId: req.user.userId,
            amount: withdrawalAmount
        });

        res.json({
            success: true,
            message: 'Withdrawal request submitted successfully',
            transaction: withdrawal,
            currentBalance: currentPoints
        });
    } catch (error) {
        console.error('Withdrawal processing error:', error);
        res.status(500).json({ 
            error: 'Failed to process withdrawal request',
            details: error.message,
            stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
});

app.get('/api/transactions', authenticateToken, async (req, res) => {
    try {
        const transactions = await Transaction.find({ userId: req.user.userId }).sort({ createdAt: -1 });
        res.json({ transactions });
    } catch (error) {
        console.error('Transaction fetch error:', error);
        res.status(500).json({ error: 'Failed to fetch transactions' });
    }
});

// Admin middleware
const isAdmin = async (req, res, next) => {
    try {
        console.log('Checking admin authorization');
        const authHeader = req.headers.authorization;
        console.log('Auth header:', authHeader);

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            console.log('No token provided or invalid format');
            return res.status(401).json({ error: 'No token provided' });
        }

        const token = authHeader.split(' ')[1];
        console.log('Token:', token);

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log('Decoded token:', decoded);

        const user = await User.findById(decoded.userId);
        console.log('Found user:', user);

        if (!user || user.userType !== 'admin') {
            console.log('User not found or not admin');
            return res.status(403).json({ error: 'Not authorized as admin' });
        }

        req.user = user;
        console.log('Admin authorization successful');
        next();
    } catch (error) {
        console.error('Admin authorization error:', error);
        res.status(401).json({ error: 'Invalid token', details: error.message });
    }
};

// Admin routes
app.get('/api/admin/users', isAdmin, async (req, res) => {
    try {
        console.log('Fetching all users');
        const users = await User.find({}, 'fullName phone walletBalance points activePlans');
        console.log('Found users:', users);
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.get('/api/admin/stats', isAdmin, async (req, res) => {
    try {
        console.log('Fetching admin stats');
        const totalUsers = await User.countDocuments();
        const totalTransactions = await Transaction.countDocuments();
        
        const stats = {
            totalUsers,
            totalTransactions
        };
        console.log('Stats:', stats);
        res.json(stats);
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

app.get('/api/admin/transactions', isAdmin, async (req, res) => {
    try {
        console.log('Fetching transactions with query:', req.query);
        const { type, status } = req.query;
        let query = {};
        
        if (type) query.type = type;
        if (status) query.status = status;
        
        console.log('Final query:', query);
        const transactions = await Transaction.find(query)
            .sort({ createdAt: -1 })
            .populate('userId', 'fullName phone');
        
        console.log('Found transactions:', transactions);
        res.json(transactions);
    } catch (error) {
        console.error('Error fetching transactions:', error);
        res.status(500).json({ error: 'Failed to fetch transactions' });
    }
});

app.post('/api/admin/users/:userId/wallet', isAdmin, async (req, res) => {
    try {
        const { amount, type } = req.body;
        const userId = req.params.userId;

        console.log('Wallet update request:', { userId, amount, type });

        // Validate input
        if (!amount || amount <= 0) {
            console.log('Invalid amount:', amount);
            return res.status(400).json({ error: 'Invalid amount' });
        }

        if (!['add', 'remove'].includes(type)) {
            console.log('Invalid operation type:', type);
            return res.status(400).json({ error: 'Invalid operation type' });
        }

        // Find user
        const user = await User.findById(userId);
        if (!user) {
            console.log('User not found:', userId);
            return res.status(404).json({ error: 'User not found' });
        }

        console.log('Found user:', { 
            userId: user._id, 
            name: user.fullName, 
            currentBalance: user.walletBalance 
        });

        // Calculate new balance
        const currentBalance = user.walletBalance || 0;
        let newBalance;
        
        if (type === 'add') {
            newBalance = currentBalance + amount;
        } else {
            if (currentBalance < amount) {
                console.log('Insufficient balance:', { currentBalance, amount });
                return res.status(400).json({ error: 'Insufficient balance' });
            }
            newBalance = currentBalance - amount;
        }

        console.log('Calculating new balance:', { currentBalance, amount, type, newBalance });

        // Update user's wallet balance
        user.walletBalance = newBalance;
        await user.save();

        console.log('Updated user wallet balance:', { 
            userId: user._id, 
            newBalance: user.walletBalance 
        });

        // Create transaction record
        const transaction = new Transaction({
            userId: user._id,
            type: type === 'add' ? 'admin_credit' : 'admin_debit',
            amount: amount,
            status: 'completed',
            userName: user.fullName,
            phoneNumber: user.phone,
            description: `Admin ${type === 'add' ? 'credited' : 'debited'} wallet balance`
        });
        await transaction.save();

        console.log('Created transaction record:', transaction);

        res.json({
            message: `Wallet balance ${type === 'add' ? 'added' : 'removed'} successfully`,
            newBalance
        });
    } catch (error) {
        console.error('Error updating wallet balance:', error);
        res.status(500).json({ 
            error: 'Failed to update wallet balance',
            details: error.message 
        });
    }
});

// Handle transaction approval (both deposit and withdrawal)
app.post('/api/admin/transactions/:transactionId/approve', isAdmin, async (req, res) => {
    try {
        const transaction = await Transaction.findById(req.params.transactionId);
        if (!transaction) {
            return res.status(404).json({ error: 'Transaction not found' });
        }

        if (transaction.status !== 'pending') {
            return res.status(400).json({ 
                error: 'Invalid transaction status',
                details: `Transaction status: ${transaction.status}`
            });
        }

        // Find user
        const user = await User.findById(transaction.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Handle based on transaction type
        if (transaction.type === 'deposit') {
            // Update user's wallet balance for deposit
            user.walletBalance = (user.walletBalance || 0) + transaction.amount;
            await user.save();
        } else if (transaction.type === 'withdrawal') {
            // Check points balance for withdrawal
            if ((user.points || 0) < transaction.amount) {
                return res.status(400).json({ error: 'Insufficient points balance' });
            }

            // Update user's points balance for withdrawal
            user.points = (user.points || 0) - transaction.amount;
            await user.save();
        } else {
            return res.status(400).json({ 
                error: 'Invalid transaction type',
                details: `Transaction type: ${transaction.type}`
            });
        }

        // Update transaction status
        transaction.status = 'completed';
        await transaction.save();

        res.json({ 
            message: `${transaction.type === 'deposit' ? 'Deposit' : 'Withdrawal'} request approved successfully` 
        });
    } catch (error) {
        console.error('Error approving transaction:', error);
        res.status(500).json({ 
            error: 'Failed to approve transaction',
            details: error.message 
        });
    }
});

// Handle transaction rejection (both deposit and withdrawal)
app.post('/api/admin/transactions/:transactionId/reject', isAdmin, async (req, res) => {
    try {
        const transaction = await Transaction.findById(req.params.transactionId);
        if (!transaction) {
            return res.status(404).json({ error: 'Transaction not found' });
        }

        if (transaction.status !== 'pending') {
            return res.status(400).json({ 
                error: 'Invalid transaction status',
                details: `Transaction status: ${transaction.status}`
            });
        }

        // Update transaction status
        transaction.status = 'failed';
        await transaction.save();

        res.json({ 
            message: `${transaction.type === 'deposit' ? 'Deposit' : 'Withdrawal'} request rejected successfully` 
        });
    } catch (error) {
        console.error('Error rejecting transaction:', error);
        res.status(500).json({ 
            error: 'Failed to reject transaction',
            details: error.message 
        });
    }
});

// Delete user
app.delete('/api/admin/users/:userId', isAdmin, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// Plan purchase endpoint
app.post('/api/plans/purchase', authenticateToken, async (req, res) => {
    let transaction = null;
    let pointsTransaction = null;
    try {
        console.log('Plan purchase request received:', req.body);
        const { planId, planName, planPrice } = req.body;
        
        if (!planId || !planName || !planPrice) {
            console.log('Missing required fields:', { planId, planName, planPrice });
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const userId = req.user.userId;
        
        // Get user and ensure points field exists
        const user = await User.findById(userId);
        if (!user) {
            console.log('User not found:', userId);
            return res.status(404).json({ error: 'User not found' });
        }

        // Initialize points if undefined
        if (typeof user.points === 'undefined') {
            user.points = 0;
        }

        // Check if user already has this plan active
        const now = new Date();
        const existingActivePlan = user.activePlans?.find(plan => 
            plan.planId === planId && 
            new Date(plan.endDate) > now
        );

        if (existingActivePlan) {
            console.log('User already has this plan active:', existingActivePlan);
            return res.status(400).json({ 
                error: 'You already have this plan active',
                existingPlan: existingActivePlan
            });
        }

        console.log('User before update:', {
            id: user._id,
            currentBalance: user.walletBalance,
            currentPoints: user.points,
            planPrice: planPrice
        });

        // Check if user has sufficient balance
        if (!user.walletBalance || user.walletBalance < planPrice) {
            console.log('Insufficient balance:', { 
                required: planPrice, 
                available: user.walletBalance 
            });
            return res.status(400).json({ error: 'Insufficient balance' });
        }

        // Calculate daily points based on plan price
        let dailyPoints;
        switch(planPrice) {
            case 299:
                dailyPoints = 50;
                break;
            case 720:
                dailyPoints = 80;
                break;
            case 1200:
                dailyPoints = 100;
                break;
            case 1499:
                dailyPoints = 160;
                break;
            case 2000:
                dailyPoints = 200;
                break;
            case 540:
                dailyPoints = 160;
                break;
            case 3400:
                dailyPoints = 400;
                break;
            case 1240:
                dailyPoints = 360;
                break;
            case 1799:
                dailyPoints = 600;
                break;
            default:
                dailyPoints = Math.floor(planPrice * 1.1); // Default to 10% more if price not in multiplier
        }

        console.log('Points calculation:', {
            planPrice,
            dailyPoints,
            currentPoints: user.points
        });

        // Create transactions
        transaction = new Transaction({
            userId,
            type: 'purchase',
            amount: planPrice,
            planId,
            planName,
            status: 'completed',
            description: `Purchased ${planName} plan`
        });

        pointsTransaction = new Transaction({
            userId,
            type: 'points_earned',
            amount: dailyPoints,
            status: 'completed',
            description: `Day 1 points from ${planName} plan purchase`
        });

        // Update user's wallet balance and points
        user.walletBalance = Number(user.walletBalance || 0) - Number(planPrice);
        user.points = Number(user.points || 0) + dailyPoints;

        // Add plan to user's active plans
        const planEndDate = new Date();
        // Set validity period based on plan price
        const validityDays = [540, 1240, 1799].includes(planPrice) ? 7 : 30;
        planEndDate.setDate(planEndDate.getDate() + validityDays);

        const newPlan = {
            planId,
            planName,
            purchaseDate: new Date(),
            endDate: planEndDate,
            dailyPoints: dailyPoints
        };

        // Initialize activePlans array if it doesn't exist
        if (!user.activePlans) {
            user.activePlans = [];
        }

        // Remove any expired plans with the same planId
        user.activePlans = user.activePlans.filter(plan => 
            plan.planId !== planId || new Date(plan.endDate) > now
        );

        // Add the new plan
        user.activePlans.push(newPlan);

        console.log('About to save changes:', {
            newWalletBalance: user.walletBalance,
            newPoints: user.points,
            pointsToAdd: dailyPoints,
            activePlans: user.activePlans.length
        });

        // Save all changes
        await Promise.all([
            transaction.save(),
            pointsTransaction.save(),
            user.save()
        ]);

        // Verify the changes
        const updatedUser = await User.findById(userId);
        console.log('Verification after save:', {
            userId: updatedUser._id,
            newBalance: updatedUser.walletBalance,
            newPoints: updatedUser.points,
            activePlansCount: updatedUser.activePlans.length
        });

        res.json({
            success: true,
            newBalance: updatedUser.walletBalance,
            newPoints: updatedUser.points,
            transaction,
            message: `Successfully purchased plan and added ${dailyPoints} points (Day 1 points)`
        });
    } catch (error) {
        console.error('Plan purchase error:', error);
        if (transaction?._id) {
            try {
                await Transaction.findByIdAndDelete(transaction._id);
            } catch (cleanupError) {
                console.error('Failed to clean up transaction:', cleanupError);
            }
        }
        if (pointsTransaction?._id) {
            try {
                await Transaction.findByIdAndDelete(pointsTransaction._id);
            } catch (cleanupError) {
                console.error('Failed to clean up points transaction:', cleanupError);
            }
        }
        res.status(500).json({ 
            error: error.message || 'Failed to purchase plan',
            details: error.stack
        });
    }
});

// Update points endpoint (to be called by a cron job)
async function updateDailyPoints() {
    let session = null;
    try {
        // Start transaction session
        session = await mongoose.startSession();
        session.startTransaction();

        console.log('Starting daily points update...');

        // Find all users with active plans
        const users = await User.find({ 'activePlans.0': { $exists: true } }).session(session);
        console.log(`Found ${users.length} users with active plans`);
        
        for (const user of users) {
            let totalPoints = 0;
            const now = new Date();
            
            // Calculate points for each active plan
            user.activePlans = user.activePlans.filter(plan => {
                const isActive = now <= new Date(plan.endDate);
                if (isActive) {
                    totalPoints += plan.dailyPoints;
                }
                return isActive; // Keep only active plans
            });
            
            // Update user's points if they have active plans
            if (totalPoints > 0) {
                user.points = (user.points || 0) + totalPoints;
                await user.save({ session });

                // Create transaction record for daily points
                const transaction = new Transaction({
                    userId: user._id,
                    type: 'points_earned',
                    amount: totalPoints,
                    status: 'completed',
                    description: `Daily points earned from active plans`
                });
                await transaction.save({ session });

                console.log(`Updated points for user ${user._id}: +${totalPoints} points`);
            }
        }
        
        // Commit the transaction
        await session.commitTransaction();
        console.log('Daily points update completed successfully');
        return { success: true, message: 'Points updated successfully' };
    } catch (error) {
        console.error('Error updating points:', error);
        if (session) {
            await session.abortTransaction();
        }
        throw error;
    } finally {
        if (session) {
            session.endSession();
        }
    }
}

// Schedule daily points update
cron.schedule('0 0 * * *', async () => {
    try {
        console.log('Running daily points update...');
        await updateDailyPoints();
        console.log('Points update completed successfully');
    } catch (error) {
        console.error('Error in cron job:', error);
    }
}, {
    timezone: "Asia/Kolkata" // Set timezone to IST
});

// Keep the endpoint for manual updates if needed
app.post('/api/update-points', async (req, res) => {
    try {
        const result = await updateDailyPoints();
        res.json(result);
    } catch (error) {
        console.error('Error in update points endpoint:', error);
        res.status(500).json({ 
            error: 'Failed to update points',
            details: error.message
        });
    }
});

// Endpoint to get user's referrals
app.get('/api/user/referrals', authenticateToken, async (req, res) => {
    try {
        console.log('Fetching referrals for user:', req.user.userId);
        
        const user = await User.findById(req.user.userId)
            .populate({
                path: 'referrals',
                select: 'fullName createdAt phone'
            });

        if (!user) {
            console.log('User not found:', req.user.userId);
            return res.status(404).json({ error: 'User not found' });
        }

        console.log('Found user with referrals:', {
            userId: user._id,
            referralCount: user.referrals.length,
            referralEarnings: user.referralEarnings
        });

        const referralData = {
            referrals: user.referrals.map(referral => ({
                fullName: referral.fullName || 'Anonymous',
                joinDate: referral.createdAt,
                phone: referral.phone,
                status: 'active'
            })),
            totalEarnings: user.referralEarnings || 0
        };

        console.log('Sending referral data:', referralData);
        res.json(referralData);
    } catch (error) {
        console.error('Error fetching referrals:', error);
        res.status(500).json({ 
            error: 'Failed to fetch referrals',
            details: error.message 
        });
    }
});

// Get user's referral code
app.get('/api/user/referral-code', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Generate referral code if not exists
        if (!user.referralCode) {
            user.referralCode = user.generateReferralCode();
            await user.save();
        }

        res.json({ referralCode: user.referralCode });
    } catch (error) {
        console.error('Error getting referral code:', error);
        res.status(500).json({ error: 'Failed to get referral code' });
    }
});

// Move all static file serving and page routes to the end
app.use(express.static('public', {
    maxAge: '1y',
    setHeaders: function(res, path) {
        // Set proper cache control
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        
        // Set proper content type for fonts
        if (path.endsWith('.woff2')) {
            res.setHeader('Content-Type', 'font/woff2');
        }
        
        // Remove charset from content type
        const contentType = res.getHeader('Content-Type');
        if (contentType && contentType.includes('charset=utf-8')) {
            res.setHeader('Content-Type', contentType.replace('; charset=utf-8', ''));
        }
    }
}));

// Page routes
app.get('/', (req, res) => {
    res.redirect('/login');
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

app.get('/admin-dashboard', async (req, res) => {
    try {
        // Get token from query parameters or headers
        const token = req.query.token || req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            console.log('No token provided for admin dashboard access');
            return res.redirect('/login');
        }

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Get user from token
        const user = await User.findById(decoded.userId);
        if (!user || user.userType !== 'admin') {
            console.log('User is not an admin:', {
                userId: decoded.userId,
                userType: user?.userType
            });
            return res.redirect('/dashboard');
        }

        console.log('Admin dashboard access granted:', {
            userId: user._id,
            phone: user.phone,
            userType: user.userType
        });

        res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
    } catch (error) {
        console.error('Admin dashboard access error:', error);
        res.redirect('/login');
    }
});

// Reset admin password
app.post('/api/admin/reset-password', async (req, res) => {
    try {
        console.log('Starting admin password reset...');
        
        // Hash the password directly
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash('YASHWANT123', salt);
        
        console.log('Password hashed:', {
            originalPassword: 'YASHWANT123',
            hashedPassword: hashedPassword
        });

        // Find or create admin user with the hashed password
        const admin = await User.findOneAndUpdate(
            { phone: '6262774601' },
            {
                $set: {
                    fullName: 'Admin Yash',
                    password: hashedPassword,
                    userType: 'admin',
                    walletBalance: 0,
                    points: 0
                }
            },
            {
                upsert: true,
                new: true,
                runValidators: true
            }
        );

        console.log('Admin user updated:', {
            userId: admin._id,
            phone: admin.phone,
            userType: admin.userType,
            passwordHash: admin.password
        });

        // Verify the password was saved correctly
        const isValid = await bcrypt.compare('YASHWANT123', admin.password);
        
        console.log('Password verification:', {
            isValid,
            storedHash: admin.password
        });

        res.json({ 
            message: 'Admin password reset successfully',
            passwordVerified: isValid
        });
    } catch (error) {
        console.error('Error resetting admin password:', error);
        res.status(500).json({ error: 'Failed to reset admin password' });
    }
});

// Verify admin password
app.post('/api/admin/verify-password', async (req, res) => {
    try {
        console.log('Starting admin password verification...');
        
        // Find admin user
        const admin = await User.findOne({ phone: '6262774601' });
        if (!admin) {
            console.log('Admin user not found');
            return res.status(404).json({ error: 'Admin user not found' });
        }

        console.log('Found admin user:', {
            userId: admin._id,
            phone: admin.phone,
            userType: admin.userType,
            storedHash: admin.password
        });

        // Verify password using bcrypt directly
        const isValid = await bcrypt.compare('YASHWANT123', admin.password);

        console.log('Password verification completed:', {
            userId: admin._id,
            phone: admin.phone,
            userType: admin.userType,
            isValid: isValid,
            storedHash: admin.password
        });

        res.json({ 
            isValid,
            userType: admin.userType,
            message: isValid ? 'Password is correct' : 'Password is incorrect'
        });
    } catch (error) {
        console.error('Error verifying admin password:', error);
        res.status(500).json({ error: 'Failed to verify admin password' });
    }
});

// Debug route to check admin user details
app.get('/api/admin/debug', async (req, res) => {
    try {
        const admin = await User.findOne({ phone: '6262774601' });
        if (!admin) {
            return res.status(404).json({ error: 'Admin user not found' });
        }

        res.json({
            userId: admin._id,
            phone: admin.phone,
            userType: admin.userType,
            passwordHash: admin.password,
            fullName: admin.fullName
        });
    } catch (error) {
        console.error('Error getting admin details:', error);
        res.status(500).json({ error: 'Failed to get admin details' });
    }
});

// Add the health check endpoint here
app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
});

// Keep the server alive
const keepAlive = () => {
    const renderUrl = process.env.RENDER_URL || 'https://your-app.onrender.com';
    setInterval(() => {
        fetch(`${renderUrl}/api/health`)
            .then(() => console.log('Keep-alive ping successful'))
            .catch(err => console.error('Keep-alive ping failed:', err));
    }, 14 * 60 * 1000);
};

// Create default admin function
const createDefaultAdmin = async () => {
    try {
        const adminPhone = '6262774601';
        const adminPassword = 'YASHWANT123';
        
        // Check if admin exists
        let admin = await User.findOne({ phone: adminPhone });
        
        if (!admin) {
            // Create new admin
            const hashedPassword = await bcrypt.hash(adminPassword, 10);
            admin = new User({
                fullName: 'Admin Yash',
                phone: adminPhone,
                password: hashedPassword,
                userType: 'admin',
                walletBalance: 0,
                points: 0
            });
            await admin.save();
            console.log('Default admin account created:', {
                userId: admin._id,
                phone: admin.phone,
                userType: admin.userType
            });
        } else {
            // Update existing admin if needed
            admin.userType = 'admin';
            await admin.save();
            console.log('Default admin account updated:', {
                userId: admin._id,
                phone: admin.phone,
                userType: admin.userType
            });
        }
    } catch (error) {
        console.error('Error creating/updating default admin:', error);
    }
};

// Start server function
const startServer = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('Connected to MongoDB Atlas successfully');
        
        // Create/update default admin account
        await createDefaultAdmin();
        
        const PORT = process.env.PORT || 3000;
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
            keepAlive(); // Add this line here
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
};

// Start the server
startServer();

// Update the signup endpoint to handle referral transactions
app.post('/api/signup', async (req, res) => {
    try {
        const { fullName, phone, password, referralCode } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ phone });
        if (existingUser) {
            return res.status(400).json({ error: 'Phone number already registered' });
        }

        // Create new user
        const newUser = new User({
            fullName,
            phone,
            password,
            referralCode: null // Will be generated after saving
        });

        // Handle referral if code provided
        if (referralCode) {
            const referrer = await User.findOne({ referralCode });
            if (referrer) {
                newUser.referredBy = referrer._id;
                referrer.referrals.push(newUser._id);
                await referrer.save();
            }
        }

        // Generate referral code and save user
        newUser.referralCode = newUser.generateReferralCode();
        await newUser.save();

        // Add referral bonus to new user
        await newUser.addReferralBonus(50);

        // Add referrer bonus to the referrer
        if (referralCode) {
            const referrer = await User.findOne({ referralCode });
            if (referrer) {
                await referrer.addReferrerBonus(100);
            }
        }

        // Generate token
        const token = jwt.sign(
            { userId: newUser._id },
            process.env.JWT_SECRET,
            { expiresIn: '30d' }
        );

        res.json({
            token,
            user: {
                id: newUser._id,
                fullName: newUser.fullName,
                phone: newUser.phone,
                userType: newUser.userType,
                referralCode: newUser.referralCode
            }
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'Failed to create account' });
    }
});
