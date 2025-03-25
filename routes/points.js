const express = require('express');
const router = express.Router();
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const { verifyAdminToken } = require('./admin');

// Update user points
router.post('/update-points', verifyAdminToken, async (req, res) => {
    try {
        const { phone, amount } = req.body;

        if (!phone || amount === undefined) {
            return res.status(400).json({ message: 'Phone and amount are required' });
        }

        const user = await User.findOne({ phone });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Initialize points if undefined
        if (typeof user.points === 'undefined') {
            user.points = 0;
        }

        const currentPoints = user.points || 0;
        const newPoints = currentPoints + amount;

        // Prevent negative points balance
        if (newPoints < 0) {
            return res.status(400).json({ message: 'Insufficient points balance' });
        }

        // Update user points
        user.points = newPoints;
        await user.save();

        // Create transaction record
        await Transaction.create({
            userId: user._id,
            userName: user.fullName,
            type: amount > 0 ? 'points_added' : 'points_deducted',
            amount: Math.abs(amount),
            status: 'completed',
            description: `Points ${amount > 0 ? 'added' : 'deducted'} by admin`
        });

        res.json({ 
            message: 'Points updated successfully',
            newPoints: user.points
        });
    } catch (error) {
        console.error('Error updating points:', error);
        res.status(500).json({ 
            error: 'Failed to update points',
            details: error.message
        });
    }
});

module.exports = router;