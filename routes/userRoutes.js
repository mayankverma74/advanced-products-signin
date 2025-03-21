router.post('/validate-referral', async (req, res) => {
    try {
        const { referralCode } = req.body;
        const userId = req.user._id; // Get the current user's ID from the token

        // Find the referrer by referral code
        const referrer = await User.findOne({ referralCode });
        if (!referrer) {
            return res.status(400).json({ success: false, message: 'Invalid referral code' });
        }

        // Find the current user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Check if user has already received referral bonus
        if (user.referralBonusReceived) {
            return res.status(400).json({ success: false, message: 'Referral bonus already received' });
        }

        // Check if user is trying to use their own referral code
        if (user.referralCode === referralCode) {
            return res.status(400).json({ success: false, message: 'Cannot use your own referral code' });
        }

        // Add bonus to new user (₹50)
        await user.addReferralBonus(50);
        user.referralBonusReceived = true;
        user.referredBy = referrer._id;
        await user.save();

        // Add bonus to referrer (₹100)
        await referrer.addReferrerBonus(100);

        res.json({ 
            success: true, 
            message: 'Referral code applied successfully',
            newUserBonus: 50,
            referrerBonus: 100
        });
    } catch (error) {
        console.error('Error validating referral code:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
}); 