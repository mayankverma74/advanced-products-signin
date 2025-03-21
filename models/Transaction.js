const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    type: {
        type: String,
        enum: ['deposit', 'withdrawal', 'admin_credit', 'admin_debit', 'purchase', 'points_earned'],
        required: true
    },
    amount: {
        type: Number,
        required: true,
        min: 0
    },
    userName: {
        type: String,
        required: function() { 
            return ['deposit', 'withdrawal'].includes(this.type);
        }
    },
    phoneNumber: {
        type: String,
        required: function() { 
            return ['deposit', 'withdrawal'].includes(this.type);
        }
    },
    status: {
        type: String,
        enum: ['pending', 'completed', 'failed'],
        default: 'pending'
    },
    // For deposits
    utrNumber: {
        type: String,
        required: function() { return this.type === 'deposit'; },
        validate: {
            validator: function(v) {
                return this.type !== 'deposit' || (v && v.length === 12);
            },
            message: 'UTR number must be 12 digits for deposits'
        }
    },
    // For withdrawals
    paymentMode: {
        type: String,
        enum: ['upi', 'bank', 'phonepe'],
        required: function() { return this.type === 'withdrawal'; }
    },
    paymentDetails: {
        type: String, // UPI ID or Bank details or PhonePe number
        required: function() { return this.type === 'withdrawal'; }
    },
    // For plan purchases
    planId: {
        type: String,
        required: function() { return this.type === 'purchase'; }
    },
    planName: {
        type: String,
        required: function() { return this.type === 'purchase'; }
    },
    description: {
        type: String
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('Transaction', transactionSchema);
