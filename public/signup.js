let otpTimer;
let resendTimer = 30;
let otpSent = false;

const signupForm = document.getElementById('signup-form');
const otpSection = document.getElementById('otpSection');
const submitButton = document.getElementById('submitButton');
const resendOtpButton = document.getElementById('resendOtp');
const otpTimerElement = document.getElementById('otpTimer');
const otpInput = document.getElementById('otp');

function showAlert(title, text, icon) {
    return Swal.fire({
        title,
        text,
        icon,
        confirmButtonColor: '#3085d6',
        confirmButtonText: 'OK'
    });
}

function showLoginPrompt() {
    Swal.fire({
        title: 'Already Registered',
        text: 'This phone number is already registered. Would you like to login?',
        icon: 'info',
        showCancelButton: true,
        confirmButtonColor: '#3085d6',
        cancelButtonColor: '#d33',
        confirmButtonText: 'Yes, Login',
        cancelButtonText: 'Stay here'
    }).then((result) => {
        if (result.isConfirmed) {
            window.location.href = '/login';
        }
    });
}

function startOtpTimer() {
    resendTimer = 60;
    resendOtpButton.disabled = true;
    
    otpTimer = setInterval(() => {
        otpTimerElement.textContent = `Resend OTP in ${resendTimer} seconds`;
        resendTimer--;
        
        if (resendTimer < 0) {
            clearInterval(otpTimer);
            resendOtpButton.disabled = false;
            otpTimerElement.textContent = '';
        }
    }, 1000);
}

function showOtpSection() {
    otpSection.classList.add('visible');
    submitButton.textContent = 'Verify OTP';
    otpInput.required = true;
    otpSent = true;
    startOtpTimer();
}

async function sendOTP(formData) {
    const response = await fetch('/api/signup/send-otp', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(formData)
    });

    const data = await response.json();
    
    if (!response.ok) {
        if (data.error === 'Phone number already registered') {
            showLoginPrompt();
            throw new Error('Phone number already registered');
        }
        throw new Error(data.error || 'Failed to send OTP');
    }

    Swal.fire({
        icon: 'success',
        title: 'OTP Sent Successfully! 📱',
        html: `Check your <b>WhatsApp</b> for the OTP message<br>
              <span style="font-size: 0.9em; color: #666;">OTP will expire in 5 minutes</span>`,
        showConfirmButton: true,
        confirmButtonText: 'OK, Got it!',
        confirmButtonColor: '#673ab7'
    });

    return data;
}

async function verifyOTP(phone, otp) {
    const response = await fetch('/api/signup/verify-otp', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ phone, otp })
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.error || 'Failed to verify OTP');
    }

    return data;
}

signupForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const fullName = document.getElementById('fullName').value;
    const phone = document.getElementById('phone').value;
    const password = document.getElementById('password').value;
    const otp = document.getElementById('otp').value;

    try {
        if (!otpSent) {
            // Validate input for initial submission
            if (!fullName || !phone || !password) {
                showAlert('Missing Information', 'Please fill in all required fields', 'warning');
                return;
            }

            // Validate phone number format
            if (!/^[0-9]{10}$/.test(phone)) {
                showAlert('Invalid Phone', 'Please enter a valid 10-digit phone number', 'warning');
                return;
            }

            // Validate full name format
            if (!/^[a-zA-Z\s]{3,20}$/.test(fullName)) {
                showAlert('Invalid Name', 'Full name should be 3-20 characters long and contain only letters', 'warning');
                return;
            }

            // Validate password strength
            if (password.length < 6 || password.length > 20) {
                showAlert('Invalid Password', 'Password must be 6-20 characters long', 'warning');
                return;
            }

            // Step 1: Send OTP
            await sendOTP({ fullName, phone, password });
            showOtpSection();
        } else {
            // Validate OTP format
            if (!/^[0-9]{6}$/.test(otp)) {
                showAlert('Invalid OTP', 'Please enter a valid 6-digit OTP', 'warning');
                return;
            }

            // Step 2: Verify OTP
            const verifyOtpData = await verifyOTP(phone, otp);

            // Store token and user data
            localStorage.setItem('token', verifyOtpData.token);
            localStorage.setItem('user', JSON.stringify(verifyOtpData.user));
            
            await showAlert('Success!', 'Account created successfully!', 'success');
            
            // Redirect to dashboard
            window.location.href = '/dashboard';
        }
    } catch (error) {
        if (error.message !== 'Phone number already registered') {
            showAlert('Error', error.message || 'Error during signup. Please try again.', 'error');
        }
    }
});

resendOtpButton.addEventListener('click', async () => {
    const phone = document.getElementById('phone').value;
    const fullName = document.getElementById('fullName').value;
    const password = document.getElementById('password').value;

    try {
        await sendOTP({ fullName, phone, password });
        startOtpTimer();
        showAlert('OTP Resent', 'A new OTP has been sent to your phone number', 'success');
    } catch (error) {
        if (error.message !== 'Phone number already registered') {
            showAlert('Error', error.message || 'Error resending OTP. Please try again.', 'error');
        }
    }
});
