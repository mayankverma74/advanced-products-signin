const mongoose = require('mongoose');

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
    resetPasswordOtp: {
        type: String
    },
    resetPasswordOtpExpiry: {
        type: Date
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Add index on phone number for faster queries
userSchema.index({ phone: 1 }, { unique: true });

const User = mongoose.model('User', userSchema);

module.exports = User;
