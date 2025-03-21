const loginForm = document.getElementById('loginForm');

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const phone = document.getElementById('phone').value;
    const password = document.getElementById('password').value;

    // Validate input
    if (!phone || !password) {
        Swal.fire({
            icon: 'warning',
            title: 'Missing Information',
            text: 'Please fill in all fields'
        });
        return;
    }

    // Validate phone number format
    if (!/^[0-9]{10}$/.test(phone)) {
        Swal.fire({
            icon: 'error',
            title: 'Invalid Phone Number',
            text: 'Please enter a valid 10-digit phone number'
        });
        return;
    }

    try {
        console.log('Attempting login...');
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ phone, password })
        });

        const data = await response.json();
        console.log('Login response:', data);
        
        if (response.ok) {
            // Store token and user data
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            
            // Show success message and redirect
            await Swal.fire({
                icon: 'success',
                title: 'Login Successful',
                text: 'Welcome back!',
                timer: 1500,
                showConfirmButton: false
            });

            // Redirect to dashboard
            window.location.href = '/dashboard';
        } else {
            throw new Error(data.error || 'Login failed');
        }
    } catch (error) {
        console.error('Login error:', error);
        Swal.fire({
            icon: 'error',
            title: 'Login Failed',
            text: error.message || 'An error occurred during login'
        });
    }
});
