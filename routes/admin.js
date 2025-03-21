const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const Admin = require('../models/Admin');
const User = require('../models/User');
const Transaction = require('../models/Transaction');

// Middleware to verify admin token
const verifyAdminToken = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'No token provided' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const admin = await Admin.findById(decoded.id);
        if (!admin) {
            return res.status(401).json({ message: 'Invalid token' });
        }
        req.admin = admin;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

// Admin login
router.post('/login', async (req, res) => {
    try {
        const { phone, password } = req.body;
        const admin = await Admin.findOne({ phone });
        
        if (!admin || !(await admin.comparePassword(password))) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Get all users
router.get('/users', verifyAdminToken, async (req, res) => {
    try {
        const users = await User.find({}, 'fullName phone wallet');
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Update user wallet
router.post('/update-wallet', verifyAdminToken, async (req, res) => {
    try {
        const { phone, amount, isAdd } = req.body;
        const user = await User.findOne({ phone });
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const currentBalance = user.wallet || 0;
        const newBalance = isAdd ? currentBalance + amount : currentBalance - amount;

        if (!isAdd && newBalance < 0) {
            return res.status(400).json({ message: 'Insufficient balance' });
        }

        user.wallet = newBalance;
        await user.save();

        // Create transaction record
        await Transaction.create({
            userId: user._id,
            userName: user.fullName,
            type: isAdd ? 'admin_add' : 'admin_remove',
            amount,
            status: 'completed'
        });

        res.json({ message: 'Wallet updated successfully', newBalance });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Get all transactions
router.get('/transactions', verifyAdminToken, async (req, res) => {
    try {
        const { type, status } = req.query;
        let query = {};
        
        if (type) query.type = type;
        if (status) query.status = status;
        
        const transactions = await Transaction.find(query)
            .populate('userId', 'fullName phone')
            .sort({ createdAt: -1 });
        res.json(transactions);
    } catch (error) {
        console.error('Error fetching transactions:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Approve deposit
router.post('/approve-deposit', verifyAdminToken, async (req, res) => {
    try {
        const { transactionId } = req.body;
        const transaction = await Transaction.findById(transactionId);
        
        if (!transaction) {
            return res.status(404).json({ message: 'Transaction not found' });
        }

        if (transaction.status !== 'pending' || transaction.type !== 'deposit') {
            return res.status(400).json({ message: 'Invalid transaction' });
        }

        const user = await User.findById(transaction.userId);
        user.wallet = (user.wallet || 0) + transaction.amount;
        await user.save();

        transaction.status = 'completed';
        await transaction.save();

        res.json({ message: 'Deposit approved successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Approve withdrawal
router.post('/approve-withdrawal', verifyAdminToken, async (req, res) => {
    try {
        const { transactionId } = req.body;
        const transaction = await Transaction.findById(transactionId);
        
        if (!transaction) {
            return res.status(404).json({ message: 'Transaction not found' });
        }

        if (transaction.status !== 'pending' || transaction.type !== 'withdrawal') {
            return res.status(400).json({ message: 'Invalid transaction' });
        }

        const user = await User.findById(transaction.userId);
        if ((user.wallet || 0) < transaction.amount) {
            return res.status(400).json({ message: 'Insufficient balance' });
        }

        user.wallet = (user.wallet || 0) - transaction.amount;
        await user.save();

        transaction.status = 'completed';
        await transaction.save();

        res.json({ message: 'Withdrawal approved successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router; 