// Add this at the top of the file
const API_BASE_URL = 'https://advanced-products-backend.onrender.com';

// Check if user is logged in
const token = localStorage.getItem('token');
if (!token) {
    window.location.href = 'login.html';
}

// Get user data
const user = JSON.parse(localStorage.getItem('user'));
if (user) {
    document.getElementById('userName').textContent = user.fullName;
    document.getElementById('profileName').textContent = user.fullName;
    document.getElementById('profilePhone').textContent = user.phone;
}

// Logout functionality
document.getElementById('logoutBtn').addEventListener('click', () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = 'login.html';
});

// Update all fetch calls to use API_BASE_URL
async function loadUserData() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/user`, {
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token')}`
            }
        });
        // ... rest of the function
    } catch (error) {
        console.error('Error loading user data:', error);
        // ... error handling
    }
}

// Update other functions similarly
