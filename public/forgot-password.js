let resetOtpTimer;
let resetResendTimer = 60;

// Add API base URL
const API_BASE_URL = 'https://advanced-products-backend.onrender.com';

document.getElementById('forgotPasswordLink').addEventListener('click', function(e) {
    e.preventDefault();
    document.getElementById('forgotPasswordModal').style.display = 'block';
});

// Close modal when clicking outside
window.addEventListener('click', function(e) {
    const modal = document.getElementById('forgotPasswordModal');
    if (e.target === modal) {
        modal.style.display = 'none';
        resetForm();
    }
});

function resetForm() {
    document.getElementById('stepPhone').style.display = 'block';
    document.getElementById('stepOtp').style.display = 'none';
    document.getElementById('stepNewPassword').style.display = 'none';
    document.getElementById('forgotPasswordForm').reset();
    if (resetOtpTimer) clearInterval(resetOtpTimer);
}

function startResetOtpTimer() {
    const timerDisplay = document.getElementById('resetOtpTimer');
    const resendBtn = document.getElementById('resendResetOtp');
    resetResendTimer = 60;
    resendBtn.disabled = true;
    
    resetOtpTimer = setInterval(() => {
        resetResendTimer--;
        timerDisplay.textContent = `Resend OTP in ${resetResendTimer}s`;
        
        if (resetResendTimer <= 0) {
            clearInterval(resetOtpTimer);
            resendBtn.disabled = false;
            timerDisplay.textContent = '';
        }
    }, 1000);
}

// Update send OTP function
async function sendOTP(phone) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/forgot-password/send-otp`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ phone })
        });

        const data = await response.json();

        if (response.ok) {
            Swal.fire({
                icon: 'success',
                title: 'OTP Sent Successfully! 📱',
                html: `Check your <b>WhatsApp</b> for the OTP message<br>
                      <span style="font-size: 0.9em; color: #666;">OTP will expire in 5 minutes</span>`,
                showConfirmButton: true,
                confirmButtonText: 'OK, Got it!',
                confirmButtonColor: '#673ab7'
            });
            document.getElementById('stepPhone').style.display = 'none';
            document.getElementById('stepOtp').style.display = 'block';
            startResetOtpTimer();
        } else {
            throw new Error(data.error || 'Phone number not registered');
        }
    } catch (error) {
        console.error('Send OTP error:', error);
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: error.message
        });
    }
}

// Update verify OTP function
async function verifyOTP(phone, otp) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/forgot-password/verify-otp`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ phone, otp })
        });

        const data = await response.json();

        if (response.ok) {
            document.getElementById('stepOtp').style.display = 'none';
            document.getElementById('stepNewPassword').style.display = 'block';
            if (resetOtpTimer) clearInterval(resetOtpTimer);
        } else {
            throw new Error(data.error || 'Invalid OTP');
        }
    } catch (error) {
        console.error('Verify OTP error:', error);
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: error.message
        });
    }
}

document.getElementById('sendResetOtpBtn').addEventListener('click', async function() {
    const phone = document.getElementById('resetPhone').value;
    
    if (!/^[0-9]{10}$/.test(phone)) {
        Swal.fire({
            icon: 'error',
            title: 'Invalid Phone Number',
            text: 'Please enter a valid 10-digit phone number'
        });
        return;
    }

    await sendOTP(phone);
});

document.getElementById('verifyResetOtpBtn').addEventListener('click', async function() {
    const phone = document.getElementById('resetPhone').value;
    const otp = document.getElementById('resetOtp').value;

    if (!/^[0-9]{6}$/.test(otp)) {
        Swal.fire({
            icon: 'error',
            title: 'Invalid OTP',
            text: 'Please enter a valid 6-digit OTP'
        });
        return;
    }

    await verifyOTP(phone, otp);
});

document.getElementById('resendResetOtp').addEventListener('click', async function() {
    const phone = document.getElementById('resetPhone').value;
    this.disabled = true;
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/forgot-password/resend-otp`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ phone })
        });

        const data = await response.json();

        if (response.ok) {
            Swal.fire({
                icon: 'success',
                title: 'OTP Resent Successfully! 📱',
                html: `Check your <b>WhatsApp</b> for the new OTP message<br>
                      <span style="font-size: 0.9em; color: #666;">OTP will expire in 5 minutes</span>`,
                showConfirmButton: true,
                confirmButtonText: 'OK, Got it!',
                confirmButtonColor: '#673ab7'
            });
            startResetOtpTimer();
        } else {
            throw new Error(data.error || 'Failed to resend OTP');
        }
    } catch (error) {
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: error.message
        });
    }
});

document.getElementById('forgotPasswordForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const phone = document.getElementById('resetPhone').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmNewPassword = document.getElementById('confirmNewPassword').value;

    if (newPassword !== confirmNewPassword) {
        Swal.fire({
            icon: 'error',
            title: 'Passwords Do Not Match',
            text: 'Please make sure both passwords are the same'
        });
        return;
    }

    if (newPassword.length < 6 || newPassword.length > 20) {
        Swal.fire({
            icon: 'error',
            title: 'Invalid Password',
            text: 'Password must be 6-20 characters long'
        });
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/forgot-password/reset`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ phone, newPassword })
        });

        const data = await response.json();

        if (response.ok) {
            await Swal.fire({
                icon: 'success',
                title: 'Password Updated! 🎉',
                text: 'Your password has been successfully updated. Please login with your new password.',
                confirmButtonColor: '#673ab7'
            });
            
            // Close modal and reset form
            document.getElementById('forgotPasswordModal').style.display = 'none';
            resetForm();
            
            // Redirect to login
            window.location.href = '/login';
        } else {
            throw new Error(data.error || 'Failed to update password');
        }
    } catch (error) {
        console.error('Reset password error:', error);
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: error.message
        });
    }
});
