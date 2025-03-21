const mongoose = require('mongoose');

const OTPSessionSchema = new mongoose.Schema({
    phone: { type: String, required: true, unique: true },
    sessionId: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 300 } // ✅ Auto-delete after 5 minutes
});

module.exports = mongoose.model('OTPSession', OTPSessionSchema);
