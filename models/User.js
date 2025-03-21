const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    fullName: {
        type: String,
        required: [true, 'Full name is required'],
        trim: true,
        minlength: [3, 'Full name must be at least 3 characters long']
    },
    phone: {
        type: String,
        required: [true, 'Phone number is required'],
        unique: true,
        trim: true,
        validate: {
            validator: function(v) {
                return /^[0-9]{10}$/.test(v);
            },
            message: props => `${props.value} is not a valid phone number!`
        }
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [6, 'Password must be at least 6 characters long']
    },
    userType: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    walletBalance: {
        type: Number,
        default: 0,
        min: 0
    },
    points: {
        type: Number,
        default: 0
    },
    resetPasswordOtp: {
        type: String
    },
    resetPasswordOtpExpiry: {
        type: Date
    },
    activePlans: [{
        planId: String,
        planName: String,
        dailyPoints: Number,
        startDate: Date,
        endDate: Date
    }],
    referralCode: {
        type: String,
        unique: true
    },
    referredBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    },
    referrals: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    referralEarnings: {
        type: Number,
        default: 0
    },
    referralBonusReceived: {
        type: Boolean,
        default: false
    },
    transactions: [{
        type: {
            type: String,
            enum: ['deposit', 'withdrawal', 'plan_purchase', 'referral_bonus', 'referrer_bonus', 'daily_points'],
            required: true
        },
        amount: {
            type: Number,
            required: true
        },
        description: {
            type: String,
            required: true
        },
        status: {
            type: String,
            enum: ['pending', 'completed', 'failed'],
            default: 'completed'
        },
        timestamp: {
            type: Date,
            default: Date.now
        }
    }],
    createdAt: {
        type: Date,
        default: Date.now
    }
}, { timestamps: true });

// Hash password directly in setPassword method
userSchema.methods.setPassword = async function(newPassword) {
    try {
        console.log('Setting new password for user:', {
            userId: this._id,
            phone: this.phone,
            newPassword: newPassword
        });

        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(newPassword, salt);
        
        console.log('Password hashed successfully:', {
            userId: this._id,
            phone: this.phone,
            hashedPassword: hash
        });

        this.password = hash;
        await this.save();
        
        console.log('User saved with new password:', {
            userId: this._id,
            phone: this.phone,
            finalHash: this.password
        });
    } catch (error) {
        console.error('Error setting password:', error);
        throw error;
    }
};

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
    try {
        console.log('Comparing passwords for user:', {
            userId: this._id,
            phone: this.phone,
            storedHash: this.password,
            candidatePassword: candidatePassword
        });

        const isMatch = await bcrypt.compare(candidatePassword, this.password);
        
        console.log('Password comparison result:', {
            userId: this._id,
            phone: this.phone,
            isMatch: isMatch
        });
        
        return isMatch;
    } catch (error) {
        console.error('Error comparing passwords:', error);
        throw error;
    }
};

// Add index on phone number for faster queries
userSchema.index({ phone: 1 }, { unique: true });

// Add method to generate referral code
userSchema.methods.generateReferralCode = function() {
    return `AP${this._id.toString().slice(0, 6).toUpperCase()}`;
};

// Add method to handle referral bonus
userSchema.methods.addReferralBonus = async function(amount) {
    this.walletBalance += amount;
    // Add transaction for referral bonus
    this.transactions.push({
        type: 'referral_bonus',
        amount: amount,
        description: 'Referral Bonus Received',
        status: 'completed',
        timestamp: new Date()
    });
    await this.save();
    return this.walletBalance;
};

// Add method to handle referrer bonus
userSchema.methods.addReferrerBonus = async function(amount) {
    this.walletBalance += amount;
    // Add transaction for referrer bonus
    this.transactions.push({
        type: 'referrer_bonus',
        amount: amount,
        description: 'Referrer Bonus Received',
        status: 'completed',
        timestamp: new Date()
    });
    await this.save();
    return this.walletBalance;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
