require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const axios = require("axios");
const User = require("./models/User");

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(express.json());
app.use(cors());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log("MongoDB Connected"))
  .catch(err => console.log("MongoDB Connection Error:", err));

// Generate OTP
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// Store OTP temporarily
const otpStore = {};

// Signup Route (Send OTP)
app.post("/api/send-otp", async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: "Phone number is required" });

  const otp = generateOTP();
  otpStore[phone] = otp;

  try {
    const response = await axios.get(`https://2factor.in/API/V1/${process.env.TWO_FACTOR_API_KEY}/SMS/${phone}/${otp}`);
    if (response.data.Status === "Success") {
      res.json({ message: "OTP sent successfully" });
    } else {
      res.status(500).json({ error: "Failed to send OTP" });
    }
  } catch (error) {
    res.status(500).json({ error: "OTP sending failed" });
  }
});

// Verify OTP & Register User
app.post("/api/signup", async (req, res) => {
  const { full_name, phone, password, otp } = req.body;
  if (!full_name || !phone || !password || !otp) return res.status(400).json({ error: "All fields are required" });
  
  if (otpStore[phone] !== otp) return res.status(400).json({ error: "Invalid OTP" });
  
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const user = new User({ full_name, phone, password_hash: hashedPassword });
    await user.save();
    delete otpStore[phone];
    res.json({ message: "Signup successful" });
  } catch (error) {
    res.status(500).json({ error: "Error saving user" });
  }
});

// Login Route
app.post("/api/login", async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ error: "All fields are required" });
  
  const user = await User.findOne({ phone });
  if (!user) return res.status(400).json({ error: "User not found" });
  
  const isMatch = await bcrypt.compare(password, user.password_hash);
  if (!isMatch) return res.status(400).json({ error: "Invalid password" });

  res.json({ message: "Login successful" });
});

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
