const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    full_name: String,
    phone: { type: String, unique: true },
    password_hash: String,
    created_at: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
