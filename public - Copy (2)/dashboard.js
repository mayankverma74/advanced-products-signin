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
